# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Set-Action1Credentials {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingConvertToSecureStringWithPlainText',
        '',
        Justification = 'String secrets are accepted for compatibility and converted before storage.'
    )]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ $_.Length -gt 0 })]
        [string]$APIKey,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [object]$Secret
    )

    if ($Secret -isnot [System.Security.SecureString] -and $Secret -isnot [string]) {
        Write-Error 'Secret must be a System.Security.SecureString or a string.' -Category InvalidArgument
        return
    }
    if ($Secret.Length -eq 0) {
        Write-Error 'Secret must not be empty.' -Category InvalidArgument
        return
    }
    if ($Secret -is [string]) {
        Write-Warning 'Passing Secret as a plaintext string is insecure and will be deprecated soon. Use a System.Security.SecureString instead.'
        $Secret = ConvertTo-SecureString -String $Secret -AsPlainText -Force -ErrorAction Stop
    }

    $Script:Action1_APIKey = $APIKey
    $Script:Action1_Secret = $Secret
}
