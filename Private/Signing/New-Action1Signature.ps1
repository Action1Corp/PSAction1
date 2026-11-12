# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function New-Action1Signature {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [object]$ObjectConfig,

        [string]$Action1KeyPath = $Script:Action1_SignKeyPath,

        [System.Security.SecureString]$PassPhrase = $Script:Action1_SignPassPhrase
    )

    if ($ObjectConfig -is [System.Collections.IDictionary]) {
        $propertyCount = $ObjectConfig.Count
    }
    elseif ($ObjectConfig -is [PSCustomObject]) {
        $propertyCount = @($ObjectConfig.PSObject.Properties).Count
    }
    else {
        throw 'ObjectConfig must be a dictionary or PSCustomObject configuration.'
    }
    if ($propertyCount -eq 0) {
        throw 'ObjectConfig must contain at least one configuration property.'
    }
    $setupHint = 'Run Set-Action1Sign to configure signing credentials.'
    if ($Action1KeyPath -notmatch '\S') {
        throw "The Action1 signing key path is not configured. $setupHint"
    }
    try {
        $keyFile = Get-Item -LiteralPath $Action1KeyPath -Force -ErrorAction Stop
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        throw "The Action1 signing key file '$Action1KeyPath' was not found. $setupHint"
    }
    catch {
        throw "Cannot access the Action1 signing key file '$Action1KeyPath'. Check the path and permissions. $setupHint"
    }
    if ($keyFile -isnot [IO.FileInfo]) {
        throw "The Action1 signing key path '$Action1KeyPath' must identify a filesystem file. $setupHint"
    }
    if ($keyFile.Length -eq 0) {
        throw "The Action1 signing key file '$Action1KeyPath' is empty. $setupHint"
    }
    if (-not (Test-Action1SignTool)) {
        throw 'Action1 signing tool validation failed.'
    }
    if ($null -eq $PassPhrase -or $PassPhrase.Length -eq 0) {
        throw "The Action1 signing passphrase is not configured or is empty. $setupHint"
    }
    $signToolPath = Join-Path $Script:Action1_SignToolPath $Script:Action1_SignToolFileName
    $signToolPath = (Resolve-Path -LiteralPath $signToolPath -ErrorAction Stop).ProviderPath
    $configurationJson = ConvertTo-Json -InputObject $ObjectConfig -Depth 100 -Compress `
        -ErrorAction Stop -WarningAction Stop

    $temporaryConfigFile = $null
    $plainPassphrase = $null
    $inputEncoding = $global:OutputEncoding
    $consoleEncoding = [Console]::OutputEncoding
    try {
        $temporaryPath = Join-Path $env:TEMP ('PSAction1-Signing-' + (New-Guid).Guid + '.json')
        # New-Item writes UTF-8 without a BOM or added newline in PowerShell 5.1.
        $temporaryConfigFile = (New-Item -Path $temporaryPath -ItemType File `
            -Value $configurationJson -ErrorAction Stop).FullName
        Write-Action1Debug 'Signing Action1 configuration with the validated signing tool.'
        # Windows PowerShell 5.1 uses the global encoding for native pipeline input.
        $global:OutputEncoding = New-Object Text.UTF8Encoding($false)
        [Console]::OutputEncoding = $global:OutputEncoding
        # PowerShell 5.1 has no ConvertFrom-SecureString -AsPlainText. New-Object
        # wraps the SecureString; Password exposes plaintext for the native tool.
        $plainPassphrase = (New-Object System.Net.NetworkCredential `
            -ArgumentList 'Action1', $PassPhrase -ErrorAction Stop).Password
        $errorAction = $ErrorActionPreference
        try {
            # Capture native stderr without terminating the pipeline and keep
            # diagnostics out of the returned signature and failure message.
            $ErrorActionPreference = 'Continue'
            $output = $plainPassphrase | & $signToolPath "--config=$temporaryConfigFile" `
                "--action1-key=$($keyFile.FullName)" `
                '--passphrase-file=-' 2>&1 |
                Where-Object { $_ -is [string] }
            $exitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $errorAction
        }
        if ($exitCode -ne 0) {
            throw "Action1 signing tool failed with exit code $exitCode."
        }
        $outputJson = $output -join "`n"
        if ($outputJson -notmatch '^\s*\{') {
            # ConvertFrom-Json can unwrap a one-element array in Windows PowerShell 5.1.
            throw 'Action1 signing tool must return a nonempty JSON signature object.'
        }
        try {
            $signature = ConvertFrom-Json -InputObject $outputJson -ErrorAction Stop
        }
        catch {
            throw 'Action1 signing tool did not return valid signature JSON.'
        }
        if (
            $signature -isnot [PSCustomObject] -or
            @($signature.PSObject.Properties).Count -eq 0
        ) {
            throw 'Action1 signing tool must return a nonempty JSON signature object.'
        }
        return $signature
    }
    finally {
        $plainPassphrase = $null
        $global:OutputEncoding = $inputEncoding
        [Console]::OutputEncoding = $consoleEncoding
        if ($temporaryConfigFile -and (Test-Path -LiteralPath $temporaryConfigFile)) {
            Remove-Item -LiteralPath $temporaryConfigFile -Force -ErrorAction Stop
        }
    }
}
