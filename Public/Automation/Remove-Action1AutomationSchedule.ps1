# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Remove-Action1AutomationSchedule {
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

    $scheduleLabel = "automation schedule '$AutomationInstanceId'"

    if (-not $PSCmdlet.ShouldProcess($scheduleLabel, 'Delete automation schedule')) {
        Write-Action1Debug "Skipped deleting $scheduleLabel."

        [pscustomobject]@{
            AutomationInstanceId = $AutomationInstanceId
            Status               = 'Skipped'
            Response             = $null
        }
        return
    }

    if (Initialize-Action1DefaultOrg) {
        $orgId = Get-Action1DefaultOrgId
    }

    $uriPathBuilder = Get-UriMapValue -Key 'D_AutomationSchedule'

    $uri = & $uriPathBuilder $orgId $AutomationInstanceId
    $path = "$Script:Action1_BaseURI{0}" -f $uri

    Write-Action1Debug "Deleting $scheduleLabel."

    $response = Invoke-Action1ApiRequest `
        -Method DELETE `
        -Path $path `
        -Label "Delete $scheduleLabel" `
        -RawResponse

    if ($null -eq $response) {
        Write-Error "Failed to delete $scheduleLabel."

        [pscustomobject]@{
            AutomationInstanceId = $AutomationInstanceId
            Status               = 'Failed'
            Response             = $null
        }
        return
    }

    Write-Action1Debug "$scheduleLabel was deleted successfully."

    [pscustomobject]@{
        AutomationInstanceId = $AutomationInstanceId
        Status               = 'Removed'
        Response             = $response
    }
}
