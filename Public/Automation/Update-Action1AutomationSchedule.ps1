# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Update-Action1AutomationSchedule {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AutomationInstanceId,

        [ValidateNotNullOrEmpty()]
        [object]$AutomationScheduleDefinition,

        [switch]$Force
    )

    if ($Force) {
        $ConfirmPreference = 'None'
    }

    $scheduleLabel = "automation schedule '$AutomationInstanceId'"

    if (-not $PSCmdlet.ShouldProcess($scheduleLabel, 'Update automation schedule')) {
        Write-Action1Debug "Skipped updating $scheduleLabel."
        return
    }

    if ($null -eq $AutomationScheduleDefinition) {
        Write-Error 'Specify AutomationScheduleDefinition to update an automation schedule.'
        return
    }

    $requestBody = $AutomationScheduleDefinition
    $apiVersion = Resolve-Action1AutomationApiVersion
    if ($apiVersion -eq '4.0') {
        $requestBody = Add-Action1Signature -InputObject $requestBody -ErrorAction Stop
        if ($null -eq $requestBody -or -not (Test-Action1Signature -InputObject $requestBody)) {
            Write-Error 'The signed automation schedule definition has invalid or missing signatures.'
            return
        }
    }

    if (Initialize-Action1DefaultOrg) {
        $orgId = Get-Action1DefaultOrgId
    }

    $uriPathBuilder = Get-UriMapValue -Key 'U_AutomationSchedule'

    $uri = & $uriPathBuilder $orgId $AutomationInstanceId
    $path = "$Script:Action1_BaseURI{0}" -f $uri

    Write-Action1Debug "Updating $scheduleLabel."

    $response = Invoke-Action1ApiRequest `
        -Method PATCH `
        -Path $path `
        -Label "Update $scheduleLabel" `
        -Body $requestBody

    if ($null -eq $response) {
        Write-Error "Failed to update $scheduleLabel."
        return
    }

    Write-Action1Debug "Updated $scheduleLabel."

    $response
}
