# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Initialize-Action1DefaultOrg {
    [CmdletBinding()]
    param()

    $orgId = Get-Action1DefaultOrgId
    $orgName = Get-Action1DefaultOrgName

    if ($orgId -and $orgName) {
        Write-Action1Debug 'Default organization is already initialized.'
        return $true
    }

    if ($Script:Action1_Interactive) {
        Set-Action1DefaultOrg

        $orgId = Get-Action1DefaultOrgId
        $orgName = Get-Action1DefaultOrgName

        if ($orgId -and $orgName) {
            Write-Action1Debug 'Default organization was initialized interactively.'
            return $true
        }

        throw 'Default organization was not selected.'
    }

    if (-not $orgId) {
        throw 'Default Org ID not set. Call Set-Action1DefaultOrg before making API calls.'
    }

    if (-not $orgName) {
        throw 'Default Org name not set. Call Set-Action1DefaultOrg before making API calls.'
    }
}
