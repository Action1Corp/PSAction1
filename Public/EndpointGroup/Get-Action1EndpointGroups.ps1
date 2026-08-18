# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1EndpointGroups {
    [CmdletBinding()]
    param()

    if (Initialize-Action1DefaultOrg) {
        $orgId = Get-Action1DefaultOrgId
    }

    $uriPathBuilder = Get-UriMapValue -Key 'G_EndpointGroups'

    $uri = & $uriPathBuilder $orgId
    $path = "$Script:Action1_BaseURI{0}" -f $uri

    Write-Action1Debug 'Listing endpoint groups.'

    Invoke-Action1PagedGetRequest -Path $path -Label 'Endpoint groups'
}
