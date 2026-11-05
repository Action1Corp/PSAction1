# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function New-Action1Signature {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingPlainTextForPassword', 'PassPhrasePath',
        Justification = 'This parameter contains an encrypted file path, not a passphrase.'
    )]
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [object]$ObjectConfig,

        [string]$Action1KeyPath = $Script:Action1_SignKeyPath,

        [string]$PassPhrasePath = $Script:Action1_SignPassPhrasePath
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
    if ($PassPhrasePath -notmatch '\S') {
        throw "The encrypted signing passphrase file path is not configured. $setupHint"
    }

    $credentialFiles = @(
        @{ Path = $Action1KeyPath; Label = 'Action1 signing key' }
        @{ Path = $PassPhrasePath; Label = 'encrypted signing passphrase' }
    )
    $keyFile, $passphraseFile = foreach ($credential in $credentialFiles) {
        try {
            $file = Get-Item -LiteralPath $credential.Path -Force -ErrorAction Stop
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            throw "The $($credential.Label) file '$($credential.Path)' was not found. $setupHint"
        }
        catch {
            throw (
                "Cannot access the $($credential.Label) file '$($credential.Path)'. " +
                "Check the path and permissions. $setupHint"
            )
        }
        if ($file -isnot [IO.FileInfo]) {
            throw "The $($credential.Label) path '$($credential.Path)' must identify a filesystem file. $setupHint"
        }
        if ($file.Length -eq 0) {
            throw "The $($credential.Label) file '$($credential.Path)' is empty. $setupHint"
        }
        $file
    }
    $configurationJson = ConvertTo-Json -InputObject $ObjectConfig -Depth 100 -Compress `
        -ErrorAction Stop -WarningAction Stop

    $temporaryPassphraseFile = $null
    $plainPassphrase = $null
    $inputEncoding = $global:OutputEncoding
    $consoleEncoding = [Console]::OutputEncoding
    try {
        try {
            $encryptedPassphrase = Get-Content -LiteralPath $passphraseFile.FullName `
                -Raw -Encoding ASCII -ErrorAction Stop
        }
        catch {
            throw (
                "Cannot read the encrypted signing passphrase file '$($passphraseFile.FullName)'. " +
                "Check the file permissions. $setupHint"
            )
        }
        try {
            $plainPassphrase = ConvertFrom-Action1EncryptedText -Text $encryptedPassphrase
        }
        catch {
            throw (
                "Cannot decrypt the signing passphrase file '$($passphraseFile.FullName)'. " +
                'Run Set-Action1Sign as the current Windows user to recreate the encrypted passphrase file.'
            )
        }

        $temporaryPath = Join-Path $env:TEMP ('PSAction1-Signing-' + (New-Guid).Guid + '.txt')
        # New-Item writes UTF-8 without a BOM or added newline in PowerShell 5.1.
        $temporaryPassphraseFile = (New-Item -Path $temporaryPath -ItemType File `
            -Value $plainPassphrase -ErrorAction Stop).FullName
        $plainPassphrase = $null

        if (-not (Test-Action1SignTool)) {
            throw 'Action1 signing tool validation failed.'
        }
        $signToolPath = Join-Path $Script:Action1_SignToolPath `
            $Script:Action1_SignToolFileName
        $signToolPath = (Resolve-Path -LiteralPath $signToolPath -ErrorAction Stop).ProviderPath
        Write-Action1Debug 'Signing Action1 configuration with the validated signing tool.'
        # Windows PowerShell 5.1 uses the global encoding for native pipeline input.
        $global:OutputEncoding = New-Object Text.UTF8Encoding($false)
        [Console]::OutputEncoding = $global:OutputEncoding
        $errorAction = $ErrorActionPreference
        try {
            # Capture stderr without turning native diagnostics into terminating
            # PowerShell errors, then discard it so secrets cannot reach callers.
            $ErrorActionPreference = 'Continue'
            $output = $configurationJson | & $signToolPath '--config=-' `
                "--action1-key=$($keyFile.FullName)" `
                "--passphrase-file=$temporaryPassphraseFile" 2>&1 |
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
        if ($temporaryPassphraseFile -and (Test-Path -LiteralPath $temporaryPassphraseFile)) {
            Remove-Item -LiteralPath $temporaryPassphraseFile -Force -ErrorAction Stop
        }
    }
}
