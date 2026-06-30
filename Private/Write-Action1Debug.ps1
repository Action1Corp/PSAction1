# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Write-Action1Debug {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Message = ''
    )

    if (-not $Script:Action1_DebugEnabled) {
        return
    }

    $Now = Get-Date
    $Timezone = $Now.ToString('zzz').Replace(':', '')
    $Timestamp = '{0}{1}' -f $Now.ToString('yyMMdd HH:mm:ss'), $Timezone
    $LogMessage = '{0} DEBUG Action1 - {1}' -f $Timestamp, $Message
    Write-Host $LogMessage -ForegroundColor Blue
}
