# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Remove-Action1CompensatingControlRemediations {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'All')]
        [string]$Score = 'All',
        [switch]$Force
    )

    $remediationStatus = 'Control_applied'

    $getFirstPropertyValue = {
        param(
            [Parameter(Mandatory = $true)]
            [object]$InputObject,

            [Parameter(Mandatory = $true)]
            [string[]]$PropertyName
        )

        foreach ($name in $PropertyName) {
            if ($InputObject.PSObject.Properties.Name -contains $name) {
                $value = $InputObject.$name

                if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
                    return [string]$value
                }
            }
        }

        return $null
    }

    Write-Action1Debug "Starting bulk remediation cleanup. RemediationStatus: '$remediationStatus'. Score '$Score'. Force switch: $Force."

    $vulnerabilities = @(
        Get-Action1Vulnerabilities -RemediationStatus $remediationStatus -Score $Score | Where-Object { $null -ne $_ }
    )

    $totalVulnerabilities = $vulnerabilities.Count

    Write-Host ("Found {0} vulnerabilities with remediation status '$remediationStatus' and  score '$Score'." -f $totalVulnerabilities)

    $processedVulnerabilities = 0
    $remediationsFound = 0
    $remediationsRemoved = 0
    $remediationsSkipped = 0
    $remediationsFailed = 0

    if ($totalVulnerabilities -eq 0) {
        Write-Host ("No vulnerabilities with remediation status '$remediationStatus' and  score '$Score' were found.")

        [pscustomobject]@{
            VulnerabilitiesProcessed = $processedVulnerabilities
            RemediationsFound        = $remediationsFound
            RemediationsRemoved      = $remediationsRemoved
            RemediationsSkipped      = $remediationsSkipped
            RemediationsFailed       = $remediationsFailed
            RemediationStatus        = $remediationStatus
            Score                    = $Score
        }
        return
    }

    foreach ($vulnerability in $vulnerabilities) {
        $processedVulnerabilities++

        $cveId = & $getFirstPropertyValue -InputObject $vulnerability -PropertyName @('cve_id', 'CVEId', 'cve', 'id')

        if ([string]::IsNullOrWhiteSpace($cveId)) {
            Write-Warning ("Skipping vulnerability #{0} because a CVE id could not be found." -f $processedVulnerabilities)
            $remediationsFailed++
            continue
        }

        $percentComplete = [int](($processedVulnerabilities / $totalVulnerabilities) * 100)

        Write-Progress `
            -Activity 'Removing Action1 vulnerability remediations' `
            -Status ("Processing {0} ({1} of {2})" -f $cveId, $processedVulnerabilities, $totalVulnerabilities) `
            -PercentComplete $percentComplete

        Write-Action1Debug ("Processing vulnerability '{0}' ({1} of {2})." -f $cveId, $processedVulnerabilities, $totalVulnerabilities)

        $remediations = @(
            Get-Action1VulnerabilityRemediations -CVEId $cveId |
                Where-Object { $null -ne $_ }
        )

        if ($remediations.Count -eq 0) {
            Write-Action1Debug "No remediation records found for vulnerability '$cveId'."
            continue
        }

        $remediationsFound += $remediations.Count

        Write-Host ""
        Write-Host ("Remediations to delete for {0}:" -f $cveId)
        $remediations |
            Select-Object remediation_id, id, type, user, comment, created_at, updated_at |
            Format-List |
            Out-Host

        foreach ($remediation in $remediations) {
            $remediationId = & $getFirstPropertyValue -InputObject $remediation -PropertyName @('remediation_id', 'RemediationId', 'id')

            if ([string]::IsNullOrWhiteSpace($remediationId)) {
                Write-Warning ("Skipping a remediation for vulnerability '{0}' because remediation id could not be found." -f $cveId)
                $remediationsFailed++
                continue
            }

            $result = Remove-Action1CompensatingControlRemediation -CVEId $cveId -RemediationId $remediationId -Force:$Force

            if ($null -eq $result) {
                $remediationsFailed++
                continue
            }

            switch ($result.Status) {
                'Removed' { $remediationsRemoved++ }
                'Skipped' { $remediationsSkipped++ }
                'Failed'  { $remediationsFailed++ }
                default   { $remediationsFailed++ }
            }
        }
    }

    Write-Progress -Activity 'Removing Action1 vulnerability remediations' -Completed

    Write-Host ("{0} vulnerabilities processed, {1} remediations with status '{2}' and  score '{3}' removed successfully." -f $processedVulnerabilities, $remediationsRemoved, $remediationStatus, $Score)

    [pscustomobject]@{
        VulnerabilitiesProcessed = $processedVulnerabilities
        RemediationsFound        = $remediationsFound
        RemediationsRemoved      = $remediationsRemoved
        RemediationsSkipped      = $remediationsSkipped
        RemediationsFailed       = $remediationsFailed
        RemediationStatus        = $remediationStatus
        Score                    = $Score
    }
}
