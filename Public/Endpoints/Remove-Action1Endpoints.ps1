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

        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'ByEndpointObjects',
            ValueFromPipeline = $true
        )]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$EndpointObjects,

        [switch]$Force
    )

    begin {
        $endpointTargets = New-Object System.Collections.ArrayList

        if ($Force) {
            $ConfirmPreference = 'None'
        }
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'ByEndpointObjects') {
            foreach ($endpointObject in $EndpointObjects) {
                $target = ConvertTo-Action1EndpointDeleteTarget `
                    -EndpointObject $endpointObject

                [void]$endpointTargets.Add($target)
            }
        }
        else {
            foreach ($endpointId in $EndpointIds) {
                $target = ConvertTo-Action1EndpointDeleteTarget `
                    -EndpointId $endpointId

                [void]$endpointTargets.Add($target)
            }
        }
    }

    end {
        $totalEndpointsToRemove = $endpointTargets.Count
        $processedEndpoints = 0
        $endpointsRemoved = 0
        $endpointsSkipped = 0
        $endpointsFailed = 0
        $endpointsInvalid = 0

        Write-Action1Debug "Removing $totalEndpointsToRemove endpoint(s)."

        if ($totalEndpointsToRemove -eq 0) {
            Write-Action1Debug 'No endpoints were supplied for removal.'

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

        foreach ($target in $endpointTargets) {
            $processedEndpoints++

            $progressCount = "$processedEndpoints of $totalEndpointsToRemove"
            $progressStatus = "Processing endpoint $progressCount"
            $percentComplete = [int](
                ($processedEndpoints / $totalEndpointsToRemove) * 100
            )

            if (-not [string]::IsNullOrWhiteSpace($target.EndpointId)) {
                $progressStatus = "Processing $($target.EndpointId) ($progressCount)"
            }

            Write-Progress `
                -Activity 'Removing endpoints' `
                -Status $progressStatus `
                -PercentComplete $percentComplete

            if (-not $target.IsValid) {
                Write-Action1Debug $target.ErrorMessage
                Write-Error $target.ErrorMessage
                $endpointsInvalid++

                continue
            }

            $endpointLabel = "endpoint with id '$($target.EndpointId)'"

            if ($null -ne $target.EndpointName) {
                $endpointLabel = "$endpointLabel and name '$($target.EndpointName)'"
            }

            if (-not $PSCmdlet.ShouldProcess($endpointLabel, 'Delete endpoint')) {
                Write-Action1Debug "Skipped deleting $endpointLabel."
                $endpointsSkipped++

                continue
            }

            try {
                $endpointObject = [pscustomobject]@{
                    id   = $target.EndpointId
                    name = $target.EndpointName
                }

                $result = Remove-Action1Endpoint `
                    -EndpointObject $endpointObject `
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
}
