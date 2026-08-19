# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function New-Action1EndpointGroup {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [object]$EndpointGroupDefinition,

        [switch]$Force
    )

    if ($Force) {
        $ConfirmPreference = 'None'
    }

    $groupLabel = 'endpoint group'

    if (-not $PSCmdlet.ShouldProcess($groupLabel, 'Create endpoint group')) {
        Write-Action1Debug "Skipped creating $groupLabel."
        return
    }

    if (Initialize-Action1DefaultOrg) {
        $orgId = Get-Action1DefaultOrgId
    }

    $uriPathBuilder = Get-UriMapValue -Key 'N_EndpointGroup'

    $uri = & $uriPathBuilder $orgId
    $path = "$Script:Action1_BaseURI{0}" -f $uri

    Write-Action1Debug "Creating $groupLabel."

    $response = Invoke-Action1ApiRequest `
        -Method POST `
        -Path $path `
        -Label "Create $groupLabel" `
        -Body $EndpointGroupDefinition

    if ($null -eq $response) {
        Write-Error "Failed to create $groupLabel."
        return
    }

    Write-Action1Debug "Created $groupLabel."

    $response
}
