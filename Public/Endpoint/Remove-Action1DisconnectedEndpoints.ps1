# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Remove-Action1DisconnectedEndpoints {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSShouldProcess',
        '',
        Justification = 'Deletion confirmation is handled by Remove-Action1Endpoints.'
    )]
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$DaysDisconnected = 90
    )

    $currentTime = (Get-Date).ToUniversalTime()
    $filterTime = $currentTime.AddDays(-$DaysDisconnected)
    $filterTimeText = $filterTime.ToString('yyyy-MM-dd HH:mm:ss')

    Write-Action1Debug (
        "Getting disconnected endpoints last seen on or before '$filterTimeText'."
    )

    $disconnectedEndpoints = @(Get-Action1Endpoints -Status Disconnected)

    Write-Action1Debug (
        "Retrieved $($disconnectedEndpoints.Count) disconnected endpoint record(s)."
    )

    $requiredProperties = @('id', 'name', 'last_seen')
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
        $endpointName = [string]$endpoint.name
        $lastSeenText = [string]$endpoint.last_seen

        if ([string]::IsNullOrWhiteSpace($endpointId)) {
            Write-Action1Debug (
                "Skipping endpoint with name '$endpointName' because id is empty."
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
            $lastSeen = ConvertFrom-UtcTimestamp `
                -Timestamp $lastSeenText `
                -Template $Script:Action1_ApiTimestampTemplate
        }
        catch {
            Write-Action1Debug (
                "Skip endpoint id '{0}', name '{1}': last_seen '{2}' not '{3}'." -f
                $endpointId,
                $endpointName,
                $lastSeenText,
                $Script:Action1_ApiTimestampTemplate
            )
            $invalidEndpoints++
            continue
        }

        if ($lastSeen -le $filterTime) {
            $endpointDisconnectedDays = [int][Math]::Floor(
                ($currentTime - $lastSeen).TotalDays
            )
            $matchedEndpointMessage = (
                "Marked to delete endpoint id '{0}', name '{1}', disconnected for {2} day(s)." -f
                $endpointId,
                $endpointName,
                $endpointDisconnectedDays
            )

            Write-Action1Debug $matchedEndpointMessage

            [void]$endpointsToRemove.Add(
                [pscustomobject]@{
                    Id       = $endpointId
                    Name     = $endpointName
                    LastSeen = $lastSeen
                }
            )
        }
    }

    Write-Action1Debug "Found $($endpointsToRemove.Count) endpoint(s) to remove."

    $totalEndpointsToRemove = $endpointsToRemove.Count
    $removalResult = Remove-Action1Endpoints -EndpointObjects $endpointsToRemove

    Write-Action1Debug (
        "Disconnected done. Processed:{0}; removed:{1}; skipped:{2}; failed:{3}." -f
        $removalResult.EndpointsRemovalProcessed,
        $removalResult.EndpointsRemoved,
        $removalResult.EndpointsSkipped,
        $removalResult.EndpointsFailed
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
