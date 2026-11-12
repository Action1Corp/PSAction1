# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1AutomationInstances {
    [CmdletBinding(DefaultParameterSetName = 'AllAutomationInstances')]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = 'AsPage')]
        [Alias('AsPage')]
        [switch]$AsPages,

        [Parameter(Mandatory = $false)]
        [ValidateScript({
            Test-Action1PageSize `
                -Value $_ `
                -Maximum $Script:Action1_PagedGetRequestDefaultLimit `
                -ParameterName 'Limit'
        })]
        [int]$Limit = $Script:Action1_PagedGetRequestDefaultLimit,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            Test-Guid -Guid $_ -Label 'EndpointId'
        })]
        [string]$EndpointId
    )

    if (Initialize-Action1DefaultOrg) {
        $orgId = Get-Action1DefaultOrgId
    }

    $uriPathBuilder = Get-UriMapValue -Key 'G_AutomationInstances'

    $uri = & $uriPathBuilder $orgId $EndpointId
    $uriParts = $uri -split '\?', 2
    $path = "$Script:Action1_BaseURI{0}" -f $uriParts[0]

    $debugMessage = 'Listing automation instances'

    if ($EndpointId) {
        $debugMessage += " for endpoint '$EndpointId'"
    }

    Write-Action1Debug "$debugMessage."

    $requestParams = @{
        Path  = $path
        Label = 'Automation instances'
        Limit = $Limit
    }

    if ($uriParts.Count -gt 1) {
        $requestParams.AddArgs = $uriParts[1]
    }

    if ($AsPages.IsPresent) {
        $requestParams.AsPages = $true
    }

    Invoke-Action1PagedGetRequest @requestParams
}
