# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Remove-Action1DuplicateEndpoints {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSShouldProcess',
        '',
        Justification = 'Deletion confirmation is handled by Remove-Action1Endpoints.'
    )]
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
                "Skip endpoint id '{0}', name '{1}': MAC empty." -f
                $endpointId,
                $endpointName
            )
            $invalidEndpoints++
            continue
        }

        if ([string]::IsNullOrWhiteSpace($lastSeenText)) {
            Write-Action1Debug (
                "Skip endpoint id '{0}', name '{1}': last_seen empty." -f
                $endpointId,
                $endpointName
            )
            $invalidEndpoints++
            continue
        }

        try {
            $lastSeen = [datetime]::ParseExact($lastSeenText, $dateFormat, $null)
        }
        catch {
            Write-Action1Debug (
                "Skip endpoint id '{0}', name '{1}': last_seen '{2}' not '{3}'." -f
                $endpointId,
                $endpointName,
                $lastSeenText,
                $dateFormat
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
                    "Endpoint with id '{0}' and name: '{1}' is newest for MAC '{2}'." -f
                    $endpointId,
                    $endpointName,
                    $normalizedMacAddress
                )
            }
            else {
                [void]$duplicateEndpointsToRemove.Add($currentEndpoint)
                Write-Action1Debug (
                    "Endpoint id '{0}', name '{1}' is duplicated by MAC '{2}'." -f
                    $endpointId,
                    $endpointName,
                    $normalizedMacAddress
                )
            }
        }
    }

    Write-Action1Debug (
        "Found $($duplicateEndpointsToRemove.Count) duplicated endpoint(s)."
    )

    $totalDuplicateEndpointsToRemove = $duplicateEndpointsToRemove.Count
    $removalResult = Remove-Action1Endpoints `
        -EndpointObjects $duplicateEndpointsToRemove

    Write-Action1Debug (
        "Duplicated done. Processed:{0}; removed:{1}; skipped:{2}; failed:{3}." -f
        $removalResult.EndpointsRemovalProcessed,
        $removalResult.EndpointsRemoved,
        $removalResult.EndpointsSkipped,
        $removalResult.EndpointsFailed
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
