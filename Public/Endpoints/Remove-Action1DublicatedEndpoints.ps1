# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Remove-Action1DublicatedEndpoints {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()

    Write-Action1Debug 'Getting all endpoints to find MAC duplicates.'

    $endpoints = @(Get-Action1Endpoints -Status All)

    Write-Action1Debug "Retrieved $($endpoints.Count) endpoint record(s)."

    $dateFormat = 'yyyy-MM-dd_HH-mm-ss'
    $endpointsByMac = @{}
    $endpointsToRemove = New-Object System.Collections.ArrayList
    $invalidEndpoints = 0

    foreach ($endpoint in $endpoints) {
        if ($null -eq $endpoint) {
            Write-Action1Debug 'Skipping null endpoint object.'
            $invalidEndpoints++
            continue
        }

        $endpointId = [string]$endpoint.id
        $mac = [string]$endpoint.MAC
        $lastSeenText = [string]$endpoint.last_seen

        if ([string]::IsNullOrWhiteSpace($endpointId)) {
            Write-Action1Debug 'Skipping endpoint object because id is empty.'
            $invalidEndpoints++
            continue
        }

        if ([string]::IsNullOrWhiteSpace($mac)) {
            Write-Action1Debug "Skipping endpoint '$endpointId' because MAC is empty."
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

        $macKey = $mac.Trim().ToUpperInvariant()
        $candidate = [pscustomobject]@{
            Id       = $endpointId
            MAC      = $mac.Trim()
            LastSeen = $lastSeen
        }

        if (-not $endpointsByMac.ContainsKey($macKey)) {
            $endpointsByMac[$macKey] = $candidate
            continue
        }

        $freshestEndpoint = $endpointsByMac[$macKey]

        if ($candidate.LastSeen -gt $freshestEndpoint.LastSeen) {
            [void]$endpointsToRemove.Add($freshestEndpoint)
            $endpointsByMac[$macKey] = $candidate
            Write-Action1Debug "Endpoint '$endpointId' is newest for MAC '$macKey'."
            continue
        }

        [void]$endpointsToRemove.Add($candidate)
        Write-Action1Debug "Endpoint '$endpointId' is duplicate for MAC '$macKey'."
    }

    Write-Action1Debug "Found $($endpointsToRemove.Count) duplicated endpoint(s)."

    $totalEndpointsToRemove = $endpointsToRemove.Count
    $processedEndpoints = 0
    $endpointsRemoved = 0
    $endpointsSkipped = 0
    $endpointsFailed = 0

    foreach ($endpoint in $endpointsToRemove) {
        $processedEndpoints++

        $endpointId = [string]$endpoint.Id
        $lastSeenText = $endpoint.LastSeen.ToString($dateFormat)
        $target = "endpoint '$endpointId'"
        $action = "Delete duplicated Action1 endpoint last seen '$lastSeenText'"
        $percentComplete = [int](($processedEndpoints / $totalEndpointsToRemove) * 100)
        $progressCount = "$processedEndpoints of $totalEndpointsToRemove"
        $progressStatus = "Processing $endpointId ($progressCount)"

        Write-Progress `
            -Activity 'Removing duplicated Action1 endpoints' `
            -Status $progressStatus `
            -PercentComplete $percentComplete

        if (-not $PSCmdlet.ShouldProcess($target, $action)) {
            Write-Action1Debug "Skipped deleting duplicated endpoint '$endpointId'."
            $endpointsSkipped++

            continue
        }

        Write-Action1Debug "Deleting duplicated endpoint '$endpointId'."

        try {
            $result = Remove-Action1Endpoint -EndpointId $endpointId -Force `
                -ErrorAction Stop
        }
        catch {
            Write-Action1Debug (
                "Failed deleting duplicated endpoint '$endpointId'. " +
                "Error: $($_.Exception.Message)"
            )
            $endpointsFailed++

            continue
        }

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

    Write-Progress -Activity 'Removing duplicated Action1 endpoints' -Completed

    Write-Action1Debug (
        "Duplicated endpoint cleanup completed. Processed: $processedEndpoints; " +
        "Removed: $endpointsRemoved; Skipped: $endpointsSkipped; " +
        "Failed: $endpointsFailed."
    )

    [pscustomobject]@{
        EndpointsTotal            = $endpoints.Count
        EndpointsDuplicated       = $totalEndpointsToRemove
        EndpointsRemovalProcessed = $processedEndpoints
        EndpointsRemoved          = $endpointsRemoved
        EndpointsSkipped          = $endpointsSkipped
        EndpointsFailed           = $endpointsFailed
        EndpointsInvalid          = $invalidEndpoints
    }
}
