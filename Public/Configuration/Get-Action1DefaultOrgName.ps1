# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1DefaultOrgName {
    [CmdletBinding()]
    param()

    Write-Action1Debug 'Getting default organization name.'
    return $Script:Action1_Default_Org_Name
}
