# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Remove-Action1Endpoints {
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High',
        DefaultParameterSetName = 'ByEndpointIds'
    )]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'ByEndpointIds')]
        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$EndpointIds,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByEndpoints')]
        [AllowNull()]
        [hashtable]$Endpoints,

        [switch]$Force
    )

    $endpointKeys = @()

    if ($PSCmdlet.ParameterSetName -eq 'ByEndpoints') {
        if ($null -ne $Endpoints) {
            $endpointKeys = @($Endpoints.Keys)
        }
    }
    else {
        if ($null -ne $EndpointIds) {
            $endpointKeys = @($EndpointIds)
        }
    }

    $totalEndpointsToRemove = $endpointKeys.Count

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

    foreach ($rawEndpointId in $endpointKeys) {
        $processedEndpoints++

        $endpointId = [string]$rawEndpointId
        $endpointName = $null
        $progressCount = "$processedEndpoints of $totalEndpointsToRemove"
        $progressStatus = "Processing endpoint $progressCount"
        $percentComplete = [int](($processedEndpoints / $totalEndpointsToRemove) * 100)

        if (
            $PSCmdlet.ParameterSetName -eq 'ByEndpoints' -and
            $null -ne $Endpoints
        ) {
            $rawEndpointName = [string]$Endpoints[$rawEndpointId]

            if (-not [string]::IsNullOrWhiteSpace($rawEndpointName)) {
                $endpointName = $rawEndpointName.Trim()
            }
        }

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

        $endpointLabel = "endpoint with id '$endpointId'"

        if ($null -ne $endpointName) {
            $endpointLabel = "$endpointLabel and name '$endpointName'"
        }

        if (-not $PSCmdlet.ShouldProcess($endpointLabel, 'Delete endpoint')) {
            Write-Action1Debug "Skipped deleting $endpointLabel."
            $endpointsSkipped++

            continue
        }

        try {
            $result = Remove-Action1Endpoint `
                -EndpointId $endpointId `
                -EndpointName $endpointName `
                -Force `
                -ErrorAction Stop
        }
        catch {
            Write-Action1Debug (
                "Failed deleting {0}. Error: {1}" -f
                $endpointLabel,
                $_.Exception.Message
            )
            $endpointsFailed++

            continue
        }

        if ($null -eq $result) {
            Write-Action1Debug "$endpointLabel removal returned no result."
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
        "Done. Processed:{0}; removed:{1}; skipped:{2}; failed:{3}; invalid:{4}." -f
        $processedEndpoints,
        $endpointsRemoved,
        $endpointsSkipped,
        $endpointsFailed,
        $endpointsInvalid
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
