# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Write-Action1Debug {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowEmptyString()]
        [string]$Message
    )

    if (-not $Script:Action1_DebugEnabled) {
        return
    }

    Write-Host ("Action1 Debug: {0}" -f $Message) -ForegroundColor Blue
}