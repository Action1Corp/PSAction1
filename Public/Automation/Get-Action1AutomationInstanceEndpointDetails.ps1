# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1AutomationInstanceEndpointDetails {
    [CmdletBinding(DefaultParameterSetName = 'AllDetails')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$AutomationInstanceId,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            Test-Guid -Guid $_ -Label 'EndpointId'
        })]
        [string]$EndpointId,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsPage')]
        [switch]$AsPage,

        [Parameter(Mandatory = $false)]
        [ValidateScript({
            Test-Action1PageSize `
                -Value $_ `
                -Maximum $Script:Action1_PagedGetRequestDefaultLimit `
                -ParameterName 'Limit'
        })]
        [int]$Limit = $Script:Action1_PagedGetRequestDefaultLimit
    )

    if (Initialize-Action1DefaultOrg) {
        $orgId = Get-Action1DefaultOrgId
    }

    $uriPathBuilder = Get-UriMapValue -Key 'G_AutomationInstanceEndpointDetails'

    $uri = & $uriPathBuilder $orgId $AutomationInstanceId $EndpointId
    $path = "$Script:Action1_BaseURI{0}" -f $uri

    $label = "Automation instance '$AutomationInstanceId' endpoint '$EndpointId' details"
    Write-Action1Debug "Listing $label."

    $requestParams = @{
        Path  = $path
        Label = $label
        Limit = $Limit
    }

    if ($AsPage.IsPresent) {
        $requestParams.AsPage = $true
    }

    Invoke-Action1PagedGetRequest @requestParams
}
