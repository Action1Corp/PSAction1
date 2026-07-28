# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function New-Action1OrganizationIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Org_ID,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Org_Name
    )

    $resolvedOrgId = [string]$Org_ID
    $resolvedOrgName = $null

    if (-not [string]::IsNullOrWhiteSpace($Org_Name)) {
        $resolvedOrgName = $Org_Name.Trim()
    }

    if ([string]::IsNullOrWhiteSpace($resolvedOrgId)) {
        return [pscustomobject]@{
            IsValid      = $false
            Org_ID       = $null
            Org_Name     = $resolvedOrgName
            OrgLabel     = $null
            ErrorMessage = 'Organization ID cannot be null, empty, or whitespace.'
        }
    }

    $resolvedOrgId = $resolvedOrgId.Trim()
    $organizationLabel = New-Action1OrganizationLabel `
        -Org_ID $resolvedOrgId `
        -Org_Name $resolvedOrgName
    $parsedGuid = [guid]::Empty

    if (-not [guid]::TryParseExact($resolvedOrgId, 'D', [ref]$parsedGuid)) {
        $errorMessage = (
            "Organization ID '$resolvedOrgId' must use the standard GUID format."
        )

        return [pscustomobject]@{
            IsValid      = $false
            Org_ID       = $resolvedOrgId
            Org_Name     = $resolvedOrgName
            OrgLabel     = $organizationLabel
            ErrorMessage = $errorMessage
        }
    }

    [pscustomobject]@{
        IsValid      = $true
        Org_ID       = $resolvedOrgId
        Org_Name     = $resolvedOrgName
        OrgLabel     = $organizationLabel
        ErrorMessage = $null
    }
}
