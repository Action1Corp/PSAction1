# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

# Converts an Organization object to the ordered item used by JSON export commands.
function ConvertTo-Action1OrganizationItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [object]$Organization
    )

    $organizationId = ([string]$Organization.Org_ID).Trim()
    $organizationName = [string]$Organization.Org_Name
    $organizationDescription = ''

    if ($null -ne $Organization.Description) {
        $organizationDescription = [string]$Organization.Description
    }

    $organizationType = [string]$Organization.Type

    if ([string]::IsNullOrWhiteSpace($organizationType)) {
        $organizationType = 'Organization'
    }

    $organizationEnterpriseId = [string]$Organization.EnterpriseId
    $baseUriValue = ([string]$Script:Action1_BaseURI).TrimEnd('/')
    $selfUri = ''

    if (
        -not [string]::IsNullOrWhiteSpace($baseUriValue) -and
        -not [string]::IsNullOrWhiteSpace($organizationId)
    ) {
        $selfUri = '{0}/organizations/{1}' -f $baseUriValue, $organizationId
    }

    [PSCustomObject][ordered]@{
        id            = $organizationId
        type          = $organizationType
        self          = $selfUri
        name          = $organizationName
        description   = $organizationDescription
        enterprise_id = $organizationEnterpriseId
    }
}
