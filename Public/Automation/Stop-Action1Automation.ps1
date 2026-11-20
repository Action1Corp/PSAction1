# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Stop-Action1Automation {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AutomationInstanceId,

        [switch]$Force
    )

    if ($Force) {
        $ConfirmPreference = 'None'
    }

    $automationLabel = "automation instance '$AutomationInstanceId'"

    if (-not $PSCmdlet.ShouldProcess($automationLabel, 'Stop automation')) {
        Write-Action1Debug "Skipped stopping $automationLabel."
        return
    }

    if (Initialize-Action1DefaultOrg) {
        $orgId = Get-Action1DefaultOrgId
    }

    $uriPathBuilder = Get-UriMapValue -Key 'N_AutomationInstanceStop'

    $uri = & $uriPathBuilder $orgId $AutomationInstanceId
    $path = "$Script:Action1_BaseURI{0}" -f $uri

    Write-Action1Debug "Stopping $automationLabel."

    $response = Invoke-Action1ApiRequest `
        -Method POST `
        -Path $path `
        -Label "Stop $automationLabel"

    if ($null -eq $response) {
        Write-Error "Failed to stop $automationLabel."
        return
    }

    Write-Action1Debug "Stopped $automationLabel."

    $response
}
