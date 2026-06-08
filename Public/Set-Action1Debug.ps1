function Set-Action1Debug {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [bool]$Enabled
    )

    $Script:Action1_DebugEnabled = $Enabled

    if ($Enabled) {
        Write-Action1Debug "Debugging enabled."
    }
}