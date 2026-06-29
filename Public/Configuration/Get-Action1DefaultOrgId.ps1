# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Get-Action1DefaultOrgId {
    [CmdletBinding()]
    param()

    Write-Action1Debug 'Getting default organization ID.'
    return $Script:Action1_Default_Org_Id
}
