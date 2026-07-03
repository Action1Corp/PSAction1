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
    $processedEndpoints = 0
    $endpointsRemoved = 0
    $endpointsSkipped = 0
    $endpointsFailed = 0

    foreach ($endpoint in $endpointsToRemove) {
        $processedEndpoints++

        $endpointId = [string]$endpoint.id
        $lastSeenText = [string]$endpoint.last_seen
        $target = "endpoint '$endpointId'"
        $action = "Delete disconnected Action1 endpoint last seen '$lastSeenText'"
        $percentComplete = [int](($processedEndpoints / $totalEndpointsToRemove) * 100)
        $progressCount = "$processedEndpoints of $totalEndpointsToRemove"
        $progressStatus = "Processing $endpointId ($progressCount)"

        Write-Progress `
            -Activity 'Removing disconnected Action1 endpoints' `
            -Status $progressStatus `
            -PercentComplete $percentComplete

        if (-not $PSCmdlet.ShouldProcess($target, $action)) {
            Write-Action1Debug "Skipped deleting disconnected endpoint '$endpointId'."
            $endpointsSkipped++

            continue
        }

        Write-Action1Debug "Deleting disconnected endpoint '$endpointId'."

        $result = Remove-Action1Endpoint -EndpointId $endpointId -Force

        if ($null -eq $result) {
            $endpointsFailed++
            continue
        }

        switch ($result.Status) {
            'Removed' { $endpointsRemoved++ }
            'Skipped' { $endpointsSkipped++ }
            'Failed'  { $endpointsFailed++ }
            default   { $endpointsFailed++ }
        }
    }

    Write-Progress -Activity 'Removing disconnected Action1 endpoints' -Completed

    Write-Action1Debug (
        "Disconnected endpoint cleanup completed. Processed: $processedEndpoints; " +
        "Removed: $endpointsRemoved; Skipped: $endpointsSkipped; " +
        "Failed: $endpointsFailed."
    )

    [pscustomobject]@{
        DisconnectedEndpointsProcessed = $disconnectedEndpoints.Count
        EndpointsMatched               = $totalEndpointsToRemove
        EndpointsRemovalProcessed      = $processedEndpoints
        EndpointsRemoved               = $endpointsRemoved
        EndpointsSkipped               = $endpointsSkipped
        EndpointsFailed                = $endpointsFailed
        DaysDisconnected               = $DaysDisconnected
    }
}
