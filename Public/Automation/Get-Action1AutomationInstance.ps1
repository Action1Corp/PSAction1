# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1AutomationInstance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$AutomationInstanceId
    )

    if (Initialize-Action1DefaultOrg) {
        $orgId = Get-Action1DefaultOrgId
    }

    $uriPathBuilder = Get-UriMapValue -Key 'G_AutomationInstance'

    $uri = & $uriPathBuilder $orgId $AutomationInstanceId
    $path = "$Script:Action1_BaseURI{0}" -f $uri

    Write-Action1Debug "Getting automation instance '$AutomationInstanceId'."

    Invoke-Action1ApiRequest `
        -Method GET `
        -Path $path `
        -Label "Automation instance '$AutomationInstanceId'"
}
