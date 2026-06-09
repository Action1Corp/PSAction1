function Initialize-Action1DefaultOrg {
    [CmdletBinding()]
    param()

    if ($null -eq $Script:Action1_Default_Org) {
        if ($Script:Action1_Interactive) {
            Set-Action1DefaultOrg

            if ($null -eq $Script:Action1_Default_Org) {
                throw "Default organization was not selected."
            }
        }
        else {
            throw "Default Org not set. Call Set-Action1DefaultOrg before making API calls."
        }
    }
    return $Script:Action1_Default_Org
}