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
    $requiredProperties = @('id', 'name', 'MAC', 'last_seen')
    $newestEndpointByMacAddress = @{}
    $duplicateEndpointsToRemove = New-Object System.Collections.ArrayList
    $invalidEndpoints = 0

    foreach ($endpoint in $endpoints) {
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
        $endpointName = [string]$endpoint.name
        $mac = [string]$endpoint.MAC
        $lastSeenText = [string]$endpoint.last_seen

        if ([string]::IsNullOrWhiteSpace($endpointId)) {
            Write-Action1Debug (
                "Skipping endpoint with name '$endpointName' because id is empty."
            )
            $invalidEndpoints++
            continue
        }

        if ([string]::IsNullOrWhiteSpace($mac)) {
            Write-Action1Debug (
                "Skipping endpoint with id '$endpointId' and name: '$endpointName' " +
                "because MAC is empty."
            )
            $invalidEndpoints++
            continue
        }

        if ([string]::IsNullOrWhiteSpace($lastSeenText)) {
            Write-Action1Debug (
                "Skipping endpoint with id '$endpointId' and name: '$endpointName' " +
                "because last_seen is empty."
            )
            $invalidEndpoints++
            continue
        }

        try {
            $lastSeen = [datetime]::ParseExact($lastSeenText, $dateFormat, $null)
        }
        catch {
            Write-Action1Debug (
                "Skipping endpoint with id '$endpointId' and name: '$endpointName' " +
                "because last_seen '$lastSeenText' does not match '$dateFormat'."
            )
            $invalidEndpoints++
            continue
        }

        $normalizedMacAddress = $mac.Trim().ToUpperInvariant()
        $currentEndpoint = [pscustomobject]@{
            Id       = $endpointId
            Name     = $endpointName
            MAC      = $mac.Trim()
            LastSeen = $lastSeen
        }

        if (-not $newestEndpointByMacAddress.ContainsKey($normalizedMacAddress)) {
            $newestEndpointByMacAddress[$normalizedMacAddress] = $currentEndpoint
        }
        else {
            $newestEndpointForMacAddress = $newestEndpointByMacAddress[
                $normalizedMacAddress
            ]

            if ($currentEndpoint.LastSeen -gt $newestEndpointForMacAddress.LastSeen) {
                [void]$duplicateEndpointsToRemove.Add($newestEndpointForMacAddress)
                $newestEndpointByMacAddress[$normalizedMacAddress] = $currentEndpoint
                Write-Action1Debug (
                    "Endpoint with id '$endpointId' and name: '$endpointName' " +
                    "is newest for MAC '$normalizedMacAddress'."
                )
            }
            else {
                [void]$duplicateEndpointsToRemove.Add($currentEndpoint)
                Write-Action1Debug (
                    "Endpoint with id '$endpointId' and name: '$endpointName' " +
                    "is duplicate for MAC '$normalizedMacAddress'."
                )
            }
        }
    }

    Write-Action1Debug (
        "Found $($duplicateEndpointsToRemove.Count) duplicated endpoint(s)."
    )

    $totalDuplicateEndpointsToRemove = $duplicateEndpointsToRemove.Count
    $duplicateEndpointIdsToRemove = @(
        $duplicateEndpointsToRemove | ForEach-Object { $_.Id }
    )
    $removalResult = Remove-Action1Endpoints -EndpointIds $duplicateEndpointIdsToRemove

    Write-Action1Debug (
        "Duplicated endpoint cleanup completed. " +
        "Processed: $($removalResult.EndpointsRemovalProcessed); " +
        "Removed: $($removalResult.EndpointsRemoved); " +
        "Skipped: $($removalResult.EndpointsSkipped); " +
        "Failed: $($removalResult.EndpointsFailed)."
    )

    [pscustomobject]@{
        EndpointsTotal            = $endpoints.Count
        EndpointsDuplicated       = $totalDuplicateEndpointsToRemove
        EndpointsRemovalSucceeded = $removalResult.Succeeded
        EndpointsRemovalProcessed = $removalResult.EndpointsRemovalProcessed
        EndpointsRemoved          = $removalResult.EndpointsRemoved
        EndpointsSkipped          = $removalResult.EndpointsSkipped
        EndpointsFailed           = $removalResult.EndpointsFailed
        EndpointsInvalid          = $invalidEndpoints
    }
}
