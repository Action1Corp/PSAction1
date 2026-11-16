# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Set-Action1Credentials {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ $_.Length -gt 0 })]
        [System.Security.SecureString]$APIKey,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ $_.Length -gt 0 })]
        [System.Security.SecureString]$Secret
    )
    $Script:Action1_APIKey = $APIKey
    $Script:Action1_Secret = $Secret
}
