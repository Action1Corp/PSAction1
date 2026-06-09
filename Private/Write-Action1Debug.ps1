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