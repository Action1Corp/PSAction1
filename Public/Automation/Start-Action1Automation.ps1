# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Start-Action1Automation {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [object]$AutomationDefinition,

        [switch]$Force
    )

    if ($Force) {
        $ConfirmPreference = 'None'
    }

    $automationLabel = 'automation'

    if (-not $PSCmdlet.ShouldProcess($automationLabel, 'Start automation')) {
        Write-Action1Debug "Skipped starting $automationLabel."
        return
    }

    if (Initialize-Action1DefaultOrg) {
        $orgId = Get-Action1DefaultOrgId
    }

    $uriPathBuilder = Get-UriMapValue -Key 'N_AutomationInstance'

    $uri = & $uriPathBuilder $orgId
    $path = "$Script:Action1_BaseURI{0}" -f $uri

    Write-Action1Debug "Starting $automationLabel."

    $response = Invoke-Action1ApiRequest `
        -Method POST `
        -Path $path `
        -Label "Start $automationLabel" `
        -Body $AutomationDefinition

    if ($null -eq $response) {
        Write-Error "Failed to start $automationLabel."
        return
    }

    Write-Action1Debug "Started $automationLabel."

    $response
}
