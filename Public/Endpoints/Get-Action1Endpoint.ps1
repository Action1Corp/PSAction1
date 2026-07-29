# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Get-Action1Endpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if (-not (Test-Guid $_)) {
                throw 'EndpointId must use the standard GUID format.'
            }

            $true
        })]
        [string]$EndpointId
    )

    if (Initialize-Action1DefaultOrg) {
        $orgId = Get-Action1DefaultOrgId
    }

    $uriPathBuilder = Get-UriMapValue -Key 'G_Endpoint'

    $uri = & $uriPathBuilder $orgId $EndpointId
    $path = "$Script:Action1_BaseURI{0}" -f $uri

    Write-Action1Debug "Getting endpoint '$EndpointId'."

    Invoke-Action1ApiRequest -Method GET -Path $path -Label "Endpoint '$EndpointId'"
}
