# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1AutomationActionTemplate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$TemplateId
    )

    $uriPathBuilder = Get-UriMapValue -Key 'G_AutomationActionTemplate'

    $uri = & $uriPathBuilder $TemplateId
    $path = "$Script:Action1_BaseURI{0}" -f $uri

    Write-Action1Debug "Getting automation action template '$TemplateId' details."

    Invoke-Action1ApiRequest `
        -Method GET `
        -Path $path `
        -Label "Automation action template '$TemplateId'"
}
