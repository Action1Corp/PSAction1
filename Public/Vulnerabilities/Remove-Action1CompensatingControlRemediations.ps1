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

    $GetFirstPropertyValue = {
        param(
            [Parameter(Mandatory = $true)]
            [object]$InputObject,

            [Parameter(Mandatory = $true)]
            [string[]]$PropertyName
        )

        foreach ($Name in $PropertyName) {
            if ($InputObject.PSObject.Properties.Name -contains $Name) {
                $Value = $InputObject.$Name

                if ($null -ne $Value -and -not [string]::IsNullOrWhiteSpace([string]$Value)) {
                    return [string]$Value
                }
            }
        }

        return $null
    }

    Write-Action1Debug "Starting bulk remediation cleanup. RemediationStatus: '$remediationStatus'. Score '$Score'. Force switch: $Force."

    $Vulnerabilities = @(
        Get-Action1Vulnerabilities -RemediationStatus $remediationStatus -Score $Score | Where-Object { $null -ne $_ }
    )

    $TotalVulnerabilities = $Vulnerabilities.Count

    Write-Host ("Found {0} vulnerabilities with remediation status '$remediationStatus' and  score '$Score'." -f $TotalVulnerabilities)

    $ProcessedVulnerabilities = 0
    $RemediationsFound = 0
    $RemediationsRemoved = 0
    $RemediationsSkipped = 0
    $RemediationsFailed = 0

    if ($TotalVulnerabilities -eq 0) {
        Write-Host ("No vulnerabilities with remediation status '$remediationStatus' and  score '$Score' were found.")

        [pscustomobject]@{
            VulnerabilitiesProcessed = $ProcessedVulnerabilities
            RemediationsFound        = $RemediationsFound
            RemediationsRemoved      = $RemediationsRemoved
            RemediationsSkipped      = $RemediationsSkipped
            RemediationsFailed       = $RemediationsFailed
            RemediationStatus        = $remediationStatus
            Score                    = $Score
        }
        return
    }

    foreach ($Vulnerability in $Vulnerabilities) {
        $ProcessedVulnerabilities++

        $CVEId = & $GetFirstPropertyValue -InputObject $Vulnerability -PropertyName @('cve_id', 'CVEId', 'cve', 'id')

        if ([string]::IsNullOrWhiteSpace($CVEId)) {
            Write-Warning ("Skipping vulnerability #{0} because a CVE id could not be found." -f $ProcessedVulnerabilities)
            $RemediationsFailed++
            continue
        }

        $PercentComplete = [int](($ProcessedVulnerabilities / $TotalVulnerabilities) * 100)

        Write-Progress `
            -Activity 'Removing Action1 vulnerability remediations' `
            -Status ("Processing {0} ({1} of {2})" -f $CVEId, $ProcessedVulnerabilities, $TotalVulnerabilities) `
            -PercentComplete $PercentComplete

        Write-Action1Debug ("Processing vulnerability '{0}' ({1} of {2})." -f $CVEId, $ProcessedVulnerabilities, $TotalVulnerabilities)

        $Remediations = @(
            Get-Action1VulnerabilityRemediations -CVEId $CVEId |
                Where-Object { $null -ne $_ }
        )

        if ($Remediations.Count -eq 0) {
            Write-Action1Debug "No remediation records found for vulnerability '$CVEId'."
            continue
        }

        $RemediationsFound += $Remediations.Count

        Write-Host ""
        Write-Host ("Remediations to delete for {0}:" -f $CVEId)
        $Remediations |
            Select-Object remediation_id, id, type, user, comment, created_at, updated_at |
            Format-List |
            Out-Host

        foreach ($Remediation in $Remediations) {
            $RemediationId = & $GetFirstPropertyValue -InputObject $Remediation -PropertyName @('remediation_id', 'RemediationId', 'id')

            if ([string]::IsNullOrWhiteSpace($RemediationId)) {
                Write-Warning ("Skipping a remediation for vulnerability '{0}' because remediation id could not be found." -f $CVEId)
                $RemediationsFailed++
                continue
            }

            $Result = Remove-Action1CompensatingControlRemediation -CVEId $CVEId -RemediationId $RemediationId -Force:$Force

            if ($null -eq $Result) {
                $RemediationsFailed++
                continue
            }

            switch ($Result.Status) {
                'Removed' { $RemediationsRemoved++ }
                'Skipped' { $RemediationsSkipped++ }
                'Failed'  { $RemediationsFailed++ }
                default   { $RemediationsFailed++ }
            }
        }
    }

    Write-Progress -Activity 'Removing Action1 vulnerability remediations' -Completed

    Write-Host ("{0} vulnerabilities processed, {1} remediations with status '{2}' and  score '{3}' removed successfully." -f $ProcessedVulnerabilities, $RemediationsRemoved, $remediationStatus, $Score)

    [pscustomobject]@{
        VulnerabilitiesProcessed = $ProcessedVulnerabilities
        RemediationsFound        = $RemediationsFound
        RemediationsRemoved      = $RemediationsRemoved
        RemediationsSkipped      = $RemediationsSkipped
        RemediationsFailed       = $RemediationsFailed
        RemediationStatus        = $remediationStatus
        Score                    = $Score
    }
}
