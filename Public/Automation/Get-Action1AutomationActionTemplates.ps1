# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1AutomationActionTemplates {
    [CmdletBinding(DefaultParameterSetName = 'AllAutomationActionTemplates')]
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
        [int]$Limit = $Script:Action1_PagedGetRequestDefaultLimit
    )

    $uriPathBuilder = Get-UriMapValue -Key 'G_AutomationActionTemplates'

    $uri = & $uriPathBuilder
    $path = "$Script:Action1_BaseURI{0}" -f $uri

    Write-Action1Debug 'Listing automation action templates.'

    $requestParams = @{
        Path  = $path
        Label = 'Automation action templates'
        Limit = $Limit
    }

    if ($AsPages.IsPresent) {
        $requestParams.AsPages = $true
    }

    Invoke-Action1PagedGetRequest @requestParams
}
