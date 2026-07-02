# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Export-Action1VulnerabilitiesEndpointsCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^CVE-\d{4}-\d{3,6}$')]
        [string[]]$CVEIds,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Overdue', 'Due_soon', 'Overdue_due_soon', 'Due_later', 'Control_applied', 'All_except_control_applied', 'All')]
        [string]$RemediationStatus = 'All',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'All')]
        [string]$Score = 'All',

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    $exportColumns = @(
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

    if (-not $PSBoundParameters.ContainsKey('Path')) {
        if (Initialize-Action1DefaultOrg) {
            $orgId = Get-Action1DefaultOrgId
        }

        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $fileName = 'Action1_{0}_VulnerabilitiesEndpoints_{1}.csv' -f $orgId, $timestamp
        $Path = Join-Path -Path (Get-Location) -ChildPath $fileName
    }

    Write-Action1Debug "Starting vulnerability endpoints CSV export to '$Path'."

    $resolvedPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path)
    $parentPath = Split-Path -Path $resolvedPath -Parent

    if (-not [string]::IsNullOrWhiteSpace($parentPath) -and -not (Test-Path -LiteralPath $parentPath)) {
        Write-Action1Debug "Creating export directory '$parentPath'."
        $null = New-Item -Path $parentPath -ItemType Directory -Force
    }

    $header = $exportColumns -join ','

    $setContentParams = @{
        LiteralPath = $resolvedPath
        Value       = $header
        Encoding    = 'UTF8'
    }

    if ($Force.IsPresent) {
        $setContentParams.Force = $true
    }

    try {
        Set-Content @setContentParams -ErrorAction Stop
    }
    catch {
        throw "Unable to initialize CSV file '$resolvedPath'. Close the file if it is open in another application, verify write permissions, or use -Force for read-only/hidden files. Error: $($_.Exception.Message)"
    }

    Write-Action1Debug "Initialized CSV file '$resolvedPath'."

    $vulnerabilityByCVEId = [ordered]@{}

    if ($PSBoundParameters.ContainsKey('CVEIds')) {
        Write-Action1Debug 'Using explicitly specified CVE identifier list. RemediationStatus and Score are not used to select CVEs.'

        foreach ($inputCVEId in $CVEIds) {
            if ([string]::IsNullOrWhiteSpace($inputCVEId)) {
                continue
            }

            $normalizedCVEId = ([string]$inputCVEId).Trim().ToUpperInvariant()

            if (-not $vulnerabilityByCVEId.Contains($normalizedCVEId)) {
                $vulnerabilityByCVEId[$normalizedCVEId] = $null
            }
        }

        foreach ($cveId in @($vulnerabilityByCVEId.Keys)) {
            try {
                Write-Action1Debug "Getting vulnerability details for '$cveId'."
                $vulnerabilityByCVEId[$cveId] = Get-Action1Vulnerability -CVEId $cveId
            }
            catch {
                Write-Action1Debug "Unable to retrieve vulnerability details for '$cveId'. CSV vulnerability metadata columns may be empty. Error: $($_.Exception.Message)"
            }
        }
    }
    else {
        Write-Action1Debug "Getting vulnerabilities with remediation status '$RemediationStatus' and score '$Score'."

        $vulnerabilities = @(Get-Action1Vulnerabilities -RemediationStatus $RemediationStatus -Score $Score)

        Write-Action1Debug "Retrieved $($vulnerabilities.Count) vulnerability record(s)."

        foreach ($vulnerability in $vulnerabilities) {
            $cveId = $vulnerability.cve_id

            if ([string]::IsNullOrWhiteSpace($cveId)) {
                Write-Action1Debug 'Skipping vulnerability object because no CVE identifier was found.'
                continue
            }

            $cveId = ([string]$cveId).Trim().ToUpperInvariant()

            if (-not $vulnerabilityByCVEId.Contains($cveId)) {
                $vulnerabilityByCVEId[$cveId] = $vulnerability
            }
        }
    }

    $cveIdsToProcess = @($vulnerabilityByCVEId.Keys)
    $totalCVEIds = $cveIdsToProcess.Count
    $totalRowsExported = 0
    $currentIndex = 0

    Write-Action1Debug "Processing $totalCVEIds unique CVE identifier(s)."

    try {
        foreach ($cveId in $cveIdsToProcess) {
            $currentIndex++
            $vulnerability = $vulnerabilityByCVEId[$cveId]

            $percentComplete = 0
            if ($totalCVEIds -gt 0) {
                $percentComplete = [Math]::Min(100, [Math]::Round(($currentIndex / $totalCVEIds) * 100, 0))
            }

            Write-Progress `
                -Activity 'Getting vulnerability endpoints' `
                -Status "Processing $cveId ($currentIndex of $totalCVEIds)" `
                -PercentComplete $percentComplete

            Write-Action1Debug "Getting endpoints affected by vulnerability '$cveId'."

            $affectedEndpoints = @(Get-Action1VulnerabilityEndpoints -CVEId $cveId)

            Write-Action1Debug "Retrieved $($affectedEndpoints.Count) endpoint record(s) for vulnerability '$cveId'."

            $rowsToWrite = New-Object System.Collections.Generic.List[object]
            $cvssScore = $vulnerability.cvss_score
            $severity = $vulnerability.base_severity
            $remediationStatusValue = $vulnerability.remediation_status

            foreach ($endpoint in $affectedEndpoints) {
                $softwareItems = @($endpoint.software | Where-Object { $null -ne $_ })

                if ($softwareItems.Count -eq 0) {
                    $rowsToWrite.Add([pscustomobject][ordered]@{
                        CVEId             = $cveId
                        CVSSScore         = $cvssScore
                        Severity          = $severity
                        RemediationStatus = $remediationStatusValue
                        EndpointId        = $endpoint.endpoint_id
                        EndpointName      = $endpoint.endpoint_name
                        ApplicationName   = $null
                        InstalledVersion  = $null
                        AvailableUpdate   = $null
                    })

                    continue
                }

                foreach ($software in $softwareItems) {
                    $installedVersions = @(
                        $software.versions |
                            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.version) } |
                            ForEach-Object { [string]$_.version }
                    )

                    $availableUpdates = @(
                        $software.available_updates |
                            ForEach-Object {
                                if (-not [string]::IsNullOrWhiteSpace([string]$_.name)) {
                                    [string]$_.name
                                }
                                elseif (-not [string]::IsNullOrWhiteSpace([string]$_.version)) {
                                    [string]$_.version
                                }
                            }
                    )

                    $rowsToWrite.Add([pscustomobject][ordered]@{
                        CVEId             = $cveId
                        CVSSScore         = $cvssScore
                        Severity          = $severity
                        RemediationStatus = $remediationStatusValue
                        EndpointId        = $endpoint.endpoint_id
                        EndpointName      = $endpoint.endpoint_name
                        ApplicationName   = $software.product_name
                        InstalledVersion  = $installedVersions -join '; '
                        AvailableUpdate   = $availableUpdates -join '; '
                    })
                }
            }

            $csvLines = @(
                $rowsToWrite |
                    Select-Object -Property $exportColumns |
                    ForEach-Object {
                        $row = $_

                        $csvFields = foreach ($column in $exportColumns) {
                            $value = $row.$column

                            if ($null -eq $value) {
                                ''
                            }
                            else {
                                $stringValue = [string]$value

                                if ($stringValue -match '[,"\r\n]') {
                                    '"{0}"' -f ($stringValue -replace '"', '""')
                                }
                                else {
                                    $stringValue
                                }
                            }
                        }

                        $csvFields -join ','
                    }
            )

            if ($csvLines.Count -gt 0) {

                $addContentParams = @{
                    LiteralPath = $resolvedPath
                    Value       = $csvLines
                    Encoding    = 'UTF8'
                }

                if ($Force.IsPresent) {
                    $addContentParams.Force = $true
                }

                Add-Content @addContentParams -ErrorAction Stop
                $totalRowsExported += $csvLines.Count
                Write-Action1Debug "Appended $($csvLines.Count) row(s) for vulnerability '$cveId' to '$resolvedPath'."
            }
            else {
                Write-Action1Debug "No CSV rows were produced for vulnerability '$cveId'."
            }
        }
    }
    finally {
        Write-Progress -Activity 'Getting vulnerability endpoints' -Completed
    }

    Write-Action1Debug "Exported $totalRowsExported vulnerability endpoint record(s) to '$resolvedPath'."
}
