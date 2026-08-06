# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

# Builds the normalized identity record used by existing Organization commands.
# The identity record trims and validates the Organization ID, preserves the
# optional Organization name for user-facing messages, and carries the derived
# OrgLabel plus an ErrorMessage so callers can handle invalid input consistently.
# Create operations should use New-Action1OrganizationLabel directly because a
# new Organization has no Action1-assigned ID before the POST request.
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

    if (-not (Test-Guid $resolvedOrgId)) {
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
