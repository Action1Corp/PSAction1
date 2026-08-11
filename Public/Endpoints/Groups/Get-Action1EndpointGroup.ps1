# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1EndpointGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupId
    )

    if (Initialize-Action1DefaultOrg) {
        $orgId = Get-Action1DefaultOrgId
    }

    $uriPathBuilder = Get-UriMapValue -Key 'G_EndpointGroup'

    $uri = & $uriPathBuilder $orgId $GroupId
    $path = "$Script:Action1_BaseURI{0}" -f $uri

    Write-Action1Debug "Getting endpoint group '$GroupId'."

    Invoke-Action1ApiRequest -Method GET -Path $path -Label "Endpoint group '$GroupId'"
}
