# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Initialize-Action1DefaultOrg {
    [CmdletBinding()]
    param()

    $Org_ID = Get-Action1DefaultOrgId
    $Org_Name = Get-Action1DefaultOrgName

    if ($Org_ID -and $Org_Name) {
        Write-Action1Debug 'Default organization is already initialized.'
        return $true
    }

    if ($Script:Action1_Interactive) {
        Set-Action1DefaultOrg

        $Org_ID = Get-Action1DefaultOrgId
        $Org_Name = Get-Action1DefaultOrgName

        if ($Org_ID -and $Org_Name) {
            Write-Action1Debug 'Default organization was initialized interactively.'
            return $true
        }

        throw 'Default organization was not selected.'
    }

    if (-not $Org_ID) {
        throw 'Default Org ID not set. Call Set-Action1DefaultOrg before making API calls.'
    }

    if (-not $Org_Name) {
        throw 'Default Org name not set. Call Set-Action1DefaultOrg before making API calls.'
    }
}
