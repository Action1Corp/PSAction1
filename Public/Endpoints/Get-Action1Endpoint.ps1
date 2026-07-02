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
            $ParsedGuid = [guid]::Empty
            [guid]::TryParseExact($_, 'D', [ref]$ParsedGuid)
        })]
        [string]$EndpointId
    )

    if (Initialize-Action1DefaultOrg) {
        $Org_ID = Get-Action1DefaultOrgId
    }

    if (-not $Script:Action1_UriMap.ContainsKey('G_Endpoint')) {
        throw "Action1 URI map key 'G_Endpoint' is not defined."
    }

    $Endpoint = & $Script:Action1_UriMap['G_Endpoint'] $Org_ID $EndpointId
    $Path = "$Script:Action1_BaseURI{0}" -f $Endpoint

    Write-Action1Debug "Getting endpoint '$EndpointId'."

    Invoke-Action1ApiRequest -Method GET -Path $Path -Label "Endpoint '$EndpointId'"
}
