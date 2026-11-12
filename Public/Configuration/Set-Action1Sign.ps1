# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Set-Action1Sign {
    [CmdletBinding(SupportsShouldProcess = $true, PositionalBinding = $false)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Action1KeyPath,

        [Parameter(Mandatory)]
        [Action1SecureStringTransformationAttribute()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]$PassPhrase,

        [switch]$Force
    )

    if ($env:OS -ne 'Windows_NT') {
        throw 'Action1 signing credentials are supported only on Windows.'
    }
    if ($Action1KeyPath -notmatch '\S') {
        throw 'The signing key file path must not be blank.'
    }

    $keyFile = Get-Item -LiteralPath $Action1KeyPath -Force -ErrorAction Stop
    if ($keyFile -isnot [System.IO.FileInfo] -or $keyFile.Length -eq 0) {
        throw 'Action1KeyPath must identify a nonempty filesystem file.'
    }

    if ($Force) {
        $ConfirmPreference = 'None'
    }
    if (-not $PSCmdlet.ShouldProcess('Current module session', 'Set Action1 signing credentials')) {
        return
    }

    $Script:Action1_SignKeyPath = $keyFile.FullName
    $Script:Action1_SignPassPhrase = $PassPhrase
    Write-Action1Debug 'Action1 signing credentials configured for the current module session.'
}
