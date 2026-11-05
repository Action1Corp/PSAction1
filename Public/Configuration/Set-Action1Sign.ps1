# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Set-Action1Sign {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingPlainTextForPassword', 'PassPhrase',
        Justification = 'Accept the website passphrase as requested and encrypt it before storage.'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingPlainTextForPassword', 'PassPhrasePath',
        Justification = 'This parameter contains a file path, not a passphrase.'
    )]
    [CmdletBinding(SupportsShouldProcess = $true, PositionalBinding = $false)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Action1KeyPath,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$PassPhrase,

        [ValidateNotNullOrEmpty()]
        [string]$PassPhrasePath = $Script:Action1_SignPassPhrasePath,

        [switch]$Force
    )

    if ($env:OS -ne 'Windows_NT') {
        throw 'Action1 signing credentials are supported only on Windows.'
    }
    if (
        $Action1KeyPath -notmatch '\S' -or
        $PassPhrasePath -notmatch '\S'
    ) {
        throw 'Signing key and passphrase file paths must not be blank.'
    }

    $keyFile = Get-Item -LiteralPath $Action1KeyPath -Force -ErrorAction Stop
    if ($keyFile -isnot [System.IO.FileInfo] -or $keyFile.Length -eq 0) {
        throw 'Action1KeyPath must identify a nonempty filesystem file.'
    }

    $provider = $null
    $drive = $null
    $passphraseFile = $PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
        $PassPhrasePath, [ref]$provider, [ref]$drive
    )
    if ($provider.Name -ne 'FileSystem') {
        throw 'PassPhrasePath must identify a filesystem file.'
    }
    if ($passphraseFile -eq $keyFile.FullName) {
        throw 'The passphrase file must not overwrite the Action1 signing key.'
    }
    if (Test-Path -LiteralPath $passphraseFile) {
        $existingFile = Get-Item -LiteralPath $passphraseFile -Force -ErrorAction Stop
        if (
            $existingFile -isnot [System.IO.FileInfo] -or
            ($existingFile.Attributes -band [IO.FileAttributes]::ReparsePoint)
        ) {
            throw 'PassPhrasePath must identify a regular file, not a directory or link.'
        }
    }

    if ($Force) {
        $ConfirmPreference = 'None'
    }
    if (-not $PSCmdlet.ShouldProcess($passphraseFile, 'Store encrypted Action1 signing credentials')) {
        return
    }

    $encryptedPassphrase = ConvertTo-Action1EncryptedText -Text $PassPhrase
    $directory = Split-Path -Path $passphraseFile -Parent
    $null = New-Item -Path $directory -ItemType Directory -Force -ErrorAction Stop
    Set-Content -LiteralPath $passphraseFile -Value $encryptedPassphrase `
        -Encoding ASCII -NoNewline -ErrorAction Stop

    $Script:Action1_SignKeyPath = $keyFile.FullName
    $Script:Action1_SignPassPhrasePath = $passphraseFile
    Write-Action1Debug 'Action1 signing key and passphrase configured successfully. The passphrase stored encrypted.'
}
