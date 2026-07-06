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
    $requiredProperties = @('id', 'last_seen')
    $endpointsToRemove = New-Object System.Collections.ArrayList
    $invalidEndpoints = 0

    foreach ($endpoint in $disconnectedEndpoints) {
        if (
            -not (
                Test-ObjectProperties `
                    -InputObject $endpoint `
                    -PropertyNames $requiredProperties `
                    -ObjectName 'endpoint object'
            )
        ) {
            $invalidEndpoints++
            continue
        }

        $endpointId = [string]$endpoint.id
        $lastSeenText = [string]$endpoint.last_seen

        if ([string]::IsNullOrWhiteSpace($endpointId)) {
            Write-Action1Debug 'Skipping endpoint object because id is empty.'
            $invalidEndpoints++
            continue
        }

        if ([string]::IsNullOrWhiteSpace($lastSeenText)) {
            Write-Action1Debug (
                "Skipping endpoint '$endpointId' because last_seen is empty."
            )
            $invalidEndpoints++
            continue
        }

        try {
            $lastSeen = [datetime]::ParseExact($lastSeenText, $dateFormat, $null)
        }
        catch {
            Write-Action1Debug (
                "Skipping endpoint '$endpointId' because last_seen '$lastSeenText' " +
                "does not match '$dateFormat'."
            )
            $invalidEndpoints++
            continue
        }

        if ($lastSeen -le $filterTime) {
            [void]$endpointsToRemove.Add(
                [pscustomobject]@{
                    Id       = $endpointId
                    LastSeen = $lastSeen
                }
            )
        }
    }

    Write-Action1Debug "Found $($endpointsToRemove.Count) endpoint(s) to remove."

    $totalEndpointsToRemove = $endpointsToRemove.Count
    $endpointIdsToRemove = @($endpointsToRemove | ForEach-Object { $_.Id })
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
        EndpointsInvalid               = $invalidEndpoints
        DaysDisconnected               = $DaysDisconnected
    }
}
