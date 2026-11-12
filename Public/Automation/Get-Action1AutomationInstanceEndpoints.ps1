# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1AutomationInstanceEndpoints {
    [CmdletBinding(DefaultParameterSetName = 'AllEndpoints')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$AutomationInstanceId,

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
        [int]$Limit = $Script:Action1_PagedGetRequestDefaultLimit
    )

    if (Initialize-Action1DefaultOrg) {
        $orgId = Get-Action1DefaultOrgId
    }

    $uriPathBuilder = Get-UriMapValue -Key 'G_AutomationInstanceEndpoints'

    $uri = & $uriPathBuilder $orgId $AutomationInstanceId
    $path = "$Script:Action1_BaseURI{0}" -f $uri

    Write-Action1Debug "Listing endpoints for automation instance '$AutomationInstanceId'."

    $requestParams = @{
        Path  = $path
        Label = "Automation instance '$AutomationInstanceId' endpoint results"
        Limit = $Limit
    }

    if ($AsPages.IsPresent) {
        $requestParams.AsPages = $true
    }

    Invoke-Action1PagedGetRequest @requestParams
}
