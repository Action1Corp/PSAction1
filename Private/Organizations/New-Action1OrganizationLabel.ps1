# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function New-Action1OrganizationLabel {
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

    if (
        [string]::IsNullOrWhiteSpace($Org_ID) -and
        [string]::IsNullOrWhiteSpace($Org_Name)
    ) {
        return $null
    }

    if ([string]::IsNullOrWhiteSpace($Org_ID)) {
        return "organization with name '$($Org_Name.Trim())'"
    }

    $organizationLabel = "organization with id '$($Org_ID.Trim())'"

    if (-not [string]::IsNullOrWhiteSpace($Org_Name)) {
        $organizationLabel = (
            "$organizationLabel and name '$($Org_Name.Trim())'"
        )
    }

    $organizationLabel
}
