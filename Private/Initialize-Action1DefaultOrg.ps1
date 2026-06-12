# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

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