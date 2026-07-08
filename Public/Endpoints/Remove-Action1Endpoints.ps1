# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Remove-Action1Endpoints {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$EndpointIds,

        [switch]$Force
    )

    $totalEndpointsToRemove = 0

    if ($null -ne $EndpointIds) {
        $totalEndpointsToRemove = $EndpointIds.Count
    }

    if ($Force) {
        $ConfirmPreference = 'None'
    }

    $processedEndpoints = 0
    $endpointsRemoved = 0
    $endpointsSkipped = 0
    $endpointsFailed = 0
    $endpointsInvalid = 0

    Write-Action1Debug "Removing $totalEndpointsToRemove endpoint(s)."

    if ($totalEndpointsToRemove -eq 0) {
        Write-Action1Debug 'No endpoint IDs were supplied for removal.'

        [pscustomobject]@{
            Succeeded                 = $true
            EndpointsRequested        = 0
            EndpointsRemovalProcessed = 0
            EndpointsRemoved          = 0
            EndpointsSkipped          = 0
            EndpointsFailed           = 0
            EndpointsInvalid          = 0
        }
        return
    }

    foreach ($rawEndpointId in $EndpointIds) {
        $processedEndpoints++

        $endpointId = [string]$rawEndpointId
        $progressCount = "$processedEndpoints of $totalEndpointsToRemove"
        $progressStatus = "Processing endpoint $progressCount"
        $percentComplete = [int](($processedEndpoints / $totalEndpointsToRemove) * 100)

        if (-not [string]::IsNullOrWhiteSpace($endpointId)) {
            $endpointId = $endpointId.Trim()
            $progressStatus = "Processing $endpointId ($progressCount)"
        }

        Write-Progress `
            -Activity 'Removing endpoints' `
            -Status $progressStatus `
            -PercentComplete $percentComplete

        if ([string]::IsNullOrWhiteSpace($endpointId)) {
            Write-Action1Debug 'Skipping endpoint removal because endpoint ID is empty.'
            Write-Error 'Endpoint ID cannot be null, empty, or whitespace.'
            $endpointsInvalid++

            continue
        }

        $parsedGuid = [guid]::Empty

        if (-not [guid]::TryParseExact($endpointId, 'D', [ref]$parsedGuid)) {
            Write-Action1Debug (
                "Skipping endpoint removal because '$endpointId' is not a GUID."
            )
            Write-Error "Endpoint ID '$endpointId' must use the standard GUID format."
            $endpointsInvalid++

            continue
        }

        $target = "endpoint '$endpointId'"

        if (-not $PSCmdlet.ShouldProcess($target, 'Delete endpoint')) {
            Write-Action1Debug "Skipped deleting endpoint '$endpointId'."
            $endpointsSkipped++

            continue
        }

        Write-Action1Debug "Deleting endpoint '$endpointId'."

        try {
            $result = Remove-Action1Endpoint -EndpointId $endpointId -Force `
                -ErrorAction Stop
        }
        catch {
            Write-Action1Debug (
                "Failed deleting endpoint '$endpointId'. " +
                "Error: $($_.Exception.Message)"
            )
            $endpointsFailed++

            continue
        }

        if ($null -eq $result) {
            Write-Action1Debug "Endpoint '$endpointId' removal returned no result."
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

    Write-Progress -Activity 'Removing endpoints' -Completed

    Write-Action1Debug (
        "Endpoint removal completed. Processed: $processedEndpoints; " +
        "Removed: $endpointsRemoved; Skipped: $endpointsSkipped; " +
        "Failed: $endpointsFailed; Invalid: $endpointsInvalid."
    )

    $succeeded = ($endpointsFailed -eq 0 -and $endpointsInvalid -eq 0)

    [pscustomobject]@{
        Succeeded                 = $succeeded
        EndpointsRequested        = $totalEndpointsToRemove
        EndpointsRemovalProcessed = $processedEndpoints
        EndpointsRemoved          = $endpointsRemoved
        EndpointsSkipped          = $endpointsSkipped
        EndpointsFailed           = $endpointsFailed
        EndpointsInvalid          = $endpointsInvalid
    }
}
