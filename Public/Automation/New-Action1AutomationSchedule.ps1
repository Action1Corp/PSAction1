# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function New-Action1AutomationSchedule {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [object]$AutomationScheduleDefinition,

        [switch]$Force
    )

    if ($Force) {
        $ConfirmPreference = 'None'
    }

    $scheduleLabel = 'automation schedule'

    if (-not $PSCmdlet.ShouldProcess($scheduleLabel, 'Create automation schedule')) {
        Write-Action1Debug "Skipped creating $scheduleLabel."
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

    $uriPathBuilder = Get-UriMapValue -Key 'N_AutomationSchedule'

    $uri = & $uriPathBuilder $orgId
    $path = "$Script:Action1_BaseURI{0}" -f $uri

    Write-Action1Debug "Creating $scheduleLabel."

    $response = Invoke-Action1ApiRequest `
        -Method POST `
        -Path $path `
        -Label "Create $scheduleLabel" `
        -Body $requestBody

    if ($null -eq $response) {
        Write-Error "Failed to create $scheduleLabel."
        return
    }

    Write-Action1Debug "Created $scheduleLabel."

    $response
}
