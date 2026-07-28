# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Get-Action1OrganizationIdentityFromObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$OrganizationObject
    )

    if ($null -eq $OrganizationObject) {
        return [pscustomobject]@{
            IsValid      = $false
            Org_ID       = $null
            Org_Name     = $null
            OrgLabel     = $null
            ErrorMessage = 'Organization object cannot be null.'
        }
    }

    $idProperty = $OrganizationObject.PSObject.Properties |
        Where-Object {
            $_.Name -eq 'id' -or
            $_.Name -eq 'OrgID' -or
            $_.Name -eq 'Org_ID'
        } |
        Select-Object -First 1

    if ($null -eq $idProperty) {
        return [pscustomobject]@{
            IsValid      = $false
            Org_ID       = $null
            Org_Name     = $null
            OrgLabel     = $null
            ErrorMessage = (
                "Organization object must include an 'id', 'OrgID', or " +
                "'Org_ID' property."
            )
        }
    }

    $orgName = $null
    $nameProperty = $OrganizationObject.PSObject.Properties |
        Where-Object {
            $_.Name -eq 'name' -or
            $_.Name -eq 'OrgName' -or
            $_.Name -eq 'Org_Name'
        } |
        Select-Object -First 1

    if ($null -ne $nameProperty) {
        $orgName = [string]$nameProperty.Value
    }

    New-Action1OrganizationIdentity `
        -Org_ID ([string]$idProperty.Value) `
        -Org_Name $orgName
}
