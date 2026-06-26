# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Export-Action1VulnerabilitiesEndpointsCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Path = (Join-Path -Path (Get-Location) -ChildPath 'Action1_VulnerabilitiesEndpoints.csv'),

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^CVE-\d{4}-\d{3,6}$')]
        [string[]]$CVEIds,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Overdue', 'Due_soon', 'Overdue_due_soon', 'Due_later', 'Control_applied', 'All_except_control_applied', 'All')]
        [string]$RemediationStatus = 'All',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'All')]
        [string]$Score = 'All'
    )

    $ExportColumns = @(
        'CVEId',
        'CVSSScore',
        'Severity',
        'RemediationStatus',
        'EndpointId',
        'EndpointName',
        'ApplicationName',
        'InstalledVersion',
        'AvailableUpdate'
    )

    Write-Action1Debug "Starting vulnerability endpoints CSV export to '$Path'."

    $ResolvedPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path)
    $ParentPath = Split-Path -Path $ResolvedPath -Parent

    if (-not [string]::IsNullOrWhiteSpace($ParentPath) -and -not (Test-Path -LiteralPath $ParentPath)) {
        Write-Action1Debug "Creating export directory '$ParentPath'."
        $null = New-Item -Path $ParentPath -ItemType Directory -Force
    }

    $Header = ($ExportColumns | ForEach-Object { '"{0}"' -f ($_ -replace '"', '""') }) -join ','
    Set-Content -LiteralPath $ResolvedPath -Value $Header -Encoding UTF8
    Write-Action1Debug "Initialized CSV file '$ResolvedPath'."

    $VulnerabilityByCVEId = [ordered]@{}

    if ($PSBoundParameters.ContainsKey('CVEIds')) {
        Write-Action1Debug 'Using explicitly specified CVE identifier list. RemediationStatus and Score are not used to select CVEs.'

        foreach ($InputCVEId in $CVEIds) {
            if ([string]::IsNullOrWhiteSpace($InputCVEId)) {
                continue
            }

            $NormalizedCVEId = ([string]$InputCVEId).Trim().ToUpperInvariant()

            if (-not $VulnerabilityByCVEId.Contains($NormalizedCVEId)) {
                $VulnerabilityByCVEId[$NormalizedCVEId] = $null
            }
        }

        foreach ($CVEId in @($VulnerabilityByCVEId.Keys)) {
            try {
                Write-Action1Debug "Getting vulnerability details for '$CVEId'."
                $VulnerabilityByCVEId[$CVEId] = Get-Action1Vulnerability -CVEId $CVEId
            }
            catch {
                Write-Action1Debug "Unable to retrieve vulnerability details for '$CVEId'. CSV vulnerability metadata columns may be empty. Error: $($_.Exception.Message)"
            }
        }
    }
    else {
        Write-Action1Debug "Getting vulnerabilities with remediation status '$RemediationStatus' and score '$Score'."

        $Vulnerabilities = @(Get-Action1Vulnerabilities -RemediationStatus $RemediationStatus -Score $Score)

        Write-Action1Debug "Retrieved $($Vulnerabilities.Count) vulnerability record(s)."

        foreach ($Vulnerability in $Vulnerabilities) {
            $CVEId = Get-PropertyValue -InputObject $Vulnerability -Name @('cve_id', 'CVEId', 'cveId', 'CVE', 'cve')

            if ([string]::IsNullOrWhiteSpace($CVEId)) {
                $FallbackId = Get-PropertyValue -InputObject $Vulnerability -Name @('id')
                if ($FallbackId -match '^CVE-\d{4}-\d{3,6}$') {
                    $CVEId = $FallbackId
                }
            }

            if ([string]::IsNullOrWhiteSpace($CVEId)) {
                Write-Action1Debug 'Skipping vulnerability object because no CVE identifier was found.'
                continue
            }

            $CVEId = ([string]$CVEId).Trim().ToUpperInvariant()

            if (-not $VulnerabilityByCVEId.Contains($CVEId)) {
                $VulnerabilityByCVEId[$CVEId] = $Vulnerability
            }
        }
    }

    $CVEIdsToProcess = @($VulnerabilityByCVEId.Keys)
    $TotalCVEIds = $CVEIdsToProcess.Count
    $TotalRowsExported = 0
    $CurrentIndex = 0

    Write-Action1Debug "Processing $TotalCVEIds unique CVE identifier(s)."

    try {
        foreach ($CVEId in $CVEIdsToProcess) {
            $CurrentIndex++
            $Vulnerability = $VulnerabilityByCVEId[$CVEId]

            $PercentComplete = 0
            if ($TotalCVEIds -gt 0) {
                $PercentComplete = [Math]::Min(100, [Math]::Round(($CurrentIndex / $TotalCVEIds) * 100, 0))
            }

            Write-Progress `
                -Activity 'Getting vulnerability endpoints' `
                -Status "Processing $CVEId ($CurrentIndex of $TotalCVEIds)" `
                -PercentComplete $PercentComplete

            Write-Action1Debug "Getting endpoints affected by vulnerability '$CVEId'."

            $AffectedEndpoints = @(Get-Action1VulnerabilityEndpoints -CVEId $CVEId)

            Write-Action1Debug "Retrieved $($AffectedEndpoints.Count) endpoint record(s) for vulnerability '$CVEId'."

            $RowsToWrite = New-Object System.Collections.Generic.List[object]

            foreach ($Endpoint in $AffectedEndpoints) {
                $SoftwareItems = @(Get-PropertyValue -InputObject $Endpoint -Name @('software', 'Software'))

                if ($SoftwareItems.Count -eq 1 -and $null -ne $SoftwareItems[0]) {
                    $NestedItems = Get-PropertyValue -InputObject $SoftwareItems[0] -Name @('items', 'Items')
                    if ($null -ne $NestedItems) {
                        $SoftwareItems = @($NestedItems)
                    }
                }

                if ($SoftwareItems.Count -eq 1 -and $null -eq $SoftwareItems[0]) {
                    $SoftwareItems = @()
                }

                if ($SoftwareItems.Count -eq 0) {
                    $RowsToWrite.Add([pscustomobject][ordered]@{
                        CVEId             = $CVEId
                        CVSSScore         = Get-PropertyValue -InputObject $Vulnerability -Name @('cvss_score', 'cvss', 'cvssScore', 'score_value')
                        Severity          = Get-PropertyValue -InputObject $Vulnerability -Name @('score', 'severity', 'Severity')
                        RemediationStatus = Get-PropertyValue -InputObject $Vulnerability -Name @('remediation_status', 'remediationStatus')
                        EndpointId        = Get-PropertyValue -InputObject $Endpoint -Name @('endpoint_id', 'endpointId', 'id')
                        EndpointName      = Get-PropertyValue -InputObject $Endpoint -Name @('endpoint_name', 'endpointName', 'computer_name', 'computerName', 'name')
                        ApplicationName   = Get-PropertyValue -InputObject $Endpoint -Name @('product_name', 'productName', 'application_name', 'applicationName')
                        InstalledVersion  = Get-PropertyValue -InputObject $Endpoint -Name @('version', 'installed_version', 'installedVersion', 'current_version', 'currentVersion')
                        AvailableUpdate   = Get-PropertyValue -InputObject $Endpoint -Name @('available_update', 'available_updates', 'availableVersion', 'fixed_version', 'fixedVersion')
                    })

                    continue
                }

                foreach ($Software in $SoftwareItems) {
                    $RowsToWrite.Add([pscustomobject][ordered]@{
                        CVEId             = $CVEId
                        CVSSScore         = Get-PropertyValue -InputObject $Vulnerability -Name @('cvss_score', 'cvss', 'cvssScore', 'score_value')
                        Severity          = Get-PropertyValue -InputObject $Vulnerability -Name @('score', 'severity', 'Severity')
                        RemediationStatus = Get-PropertyValue -InputObject $Vulnerability -Name @('remediation_status', 'remediationStatus')
                        EndpointId        = Get-PropertyValue -InputObject $Endpoint -Name @('endpoint_id', 'endpointId', 'id')
                        EndpointName      = Get-PropertyValue -InputObject $Endpoint -Name @('endpoint_name', 'endpointName', 'computer_name', 'computerName', 'name')
                        ApplicationName   = Get-PropertyValue -InputObject $Software -Name @('product_name', 'productName', 'application_name', 'applicationName', 'name')
                        InstalledVersion  = Get-PropertyValue -InputObject $Software -Name @('version', 'installed_version', 'installedVersion', 'current_version', 'currentVersion')
                        AvailableUpdate   = Get-PropertyValue -InputObject $Software -Name @('available_update', 'available_updates', 'availableVersion', 'fixed_version', 'fixedVersion')
                    })
                }
            }

            if ($RowsToWrite.Count -gt 0) {
                $RowsToWrite |
                    Select-Object -Property $ExportColumns |
                    Export-Csv -LiteralPath $ResolvedPath -NoTypeInformation -Encoding UTF8 -Append

                $TotalRowsExported += $RowsToWrite.Count
                Write-Action1Debug "Appended $($RowsToWrite.Count) row(s) for vulnerability '$CVEId' to '$ResolvedPath'."
            }
            else {
                Write-Action1Debug "No CSV rows were produced for vulnerability '$CVEId'."
            }
        }
    }
    finally {
        Write-Progress -Activity 'Getting vulnerability endpoints' -Completed
    }

    Write-Action1Debug "Exported $TotalRowsExported vulnerability endpoint record(s) to '$ResolvedPath'."
}
