# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Remove-Action1DisconnectedEndpoints {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$DaysDisconnected = 90
    )

    $filterTime = (Get-Date).AddDays(-$DaysDisconnected)
    $filterTimeText = $filterTime.ToString('yyyy-MM-dd HH:mm:ss')

    Write-Action1Debug (
        "Getting disconnected endpoints last seen on or before '$filterTimeText'."
    )

    $disconnectedEndpoints = @(Get-Action1Endpoints -Status Disconnected)

    Write-Action1Debug (
        "Retrieved $($disconnectedEndpoints.Count) disconnected endpoint record(s)."
    )

    $dateFormat = 'yyyy-MM-dd_HH-mm-ss'
    $endpointsToRemove = @(
        $disconnectedEndpoints | Where-Object {
            [datetime]::ParseExact($_.last_seen, $dateFormat, $null) -le $filterTime
        }
    )

    Write-Action1Debug "Found $($endpointsToRemove.Count) endpoint(s) to remove."

    $totalEndpointsToRemove = $endpointsToRemove.Count
    $endpointIdsToRemove = @($endpointsToRemove | ForEach-Object { $_.id })
    $removalResult = Remove-Action1Endpoints -EndpointIds $endpointIdsToRemove

    Write-Action1Debug (
        "Disconnected endpoint cleanup completed. " +
        "Processed: $($removalResult.EndpointsRemovalProcessed); " +
        "Removed: $($removalResult.EndpointsRemoved); " +
        "Skipped: $($removalResult.EndpointsSkipped); " +
        "Failed: $($removalResult.EndpointsFailed)."
    )

    [pscustomobject]@{
        DisconnectedEndpointsProcessed = $disconnectedEndpoints.Count
        EndpointsMatched               = $totalEndpointsToRemove
        EndpointsRemovalSucceeded      = $removalResult.Succeeded
        EndpointsRemovalProcessed      = $removalResult.EndpointsRemovalProcessed
        EndpointsRemoved               = $removalResult.EndpointsRemoved
        EndpointsSkipped               = $removalResult.EndpointsSkipped
        EndpointsFailed                = $removalResult.EndpointsFailed
        DaysDisconnected               = $DaysDisconnected
    }
}
