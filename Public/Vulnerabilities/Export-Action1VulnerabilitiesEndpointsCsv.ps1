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
        [string]$Path = (Join-Path -Path (Get-Location) -ChildPath 'Action1_VulnerabilitiesEndpoints.csv'),

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

    $Header = $ExportColumns -join ','

    $SetContentParams = @{
        LiteralPath = $ResolvedPath
        Value       = $Header
        Encoding    = 'UTF8'
    }

    if ($Force.IsPresent) {
        $SetContentParams.Force = $true
    }

    try {
        Set-Content @SetContentParams
    }
    catch {
        throw "Unable to initialize CSV file '$ResolvedPath'. Close the file if it is open in another application, verify write permissions, or use -Force for read-only/hidden files. Error: $($_.Exception.Message)"
    }

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
            $CVEId = $Vulnerability.cve_id

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
            $CVSSScore = $Vulnerability.cvss_score
            $Severity = $Vulnerability.base_severity
            $RemediationStatusValue = $Vulnerability.remediation_status

            foreach ($Endpoint in $AffectedEndpoints) {
                $SoftwareItems = @($Endpoint.software | Where-Object { $null -ne $_ })

                if ($SoftwareItems.Count -eq 0) {
                    $RowsToWrite.Add([pscustomobject][ordered]@{
                        CVEId             = $CVEId
                        CVSSScore         = $CVSSScore
                        Severity          = $Severity
                        RemediationStatus = $RemediationStatusValue
                        EndpointId        = $Endpoint.endpoint_id
                        EndpointName      = $Endpoint.endpoint_name
                        ApplicationName   = $null
                        InstalledVersion  = $null
                        AvailableUpdate   = $null
                    })

                    continue
                }

                foreach ($Software in $SoftwareItems) {
                    $InstalledVersions = @(
                        $Software.versions |
                            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.version) } |
                            ForEach-Object { [string]$_.version }
                    )

                    $AvailableUpdates = @(
                        $Software.available_updates |
                            ForEach-Object {
                                if (-not [string]::IsNullOrWhiteSpace([string]$_.name)) {
                                    [string]$_.name
                                }
                                elseif (-not [string]::IsNullOrWhiteSpace([string]$_.version)) {
                                    [string]$_.version
                                }
                            }
                    )

                    $RowsToWrite.Add([pscustomobject][ordered]@{
                        CVEId             = $CVEId
                        CVSSScore         = $CVSSScore
                        Severity          = $Severity
                        RemediationStatus = $RemediationStatusValue
                        EndpointId        = $Endpoint.endpoint_id
                        EndpointName      = $Endpoint.endpoint_name
                        ApplicationName   = $Software.product_name
                        InstalledVersion  = $InstalledVersions -join '; '
                        AvailableUpdate   = $AvailableUpdates -join '; '
                    })
                }
            }

            $CsvLines = @(
                $RowsToWrite |
                    Select-Object -Property $ExportColumns |
                    ForEach-Object {
                        $Row = $_

                        $CsvFields = foreach ($Column in $ExportColumns) {
                            $Value = $Row.$Column

                            if ($null -eq $Value) {
                                ''
                            }
                            else {
                                $StringValue = [string]$Value

                                if ($StringValue -match '[,"\r\n]') {
                                    '"{0}"' -f ($StringValue -replace '"', '""')
                                }
                                else {
                                    $StringValue
                                }
                            }
                        }

                        $CsvFields -join ','
                    }
            )

            if ($CsvLines.Count -gt 0) {

                $AddContentParams = @{
                    LiteralPath = $ResolvedPath
                    Value       = $CsvLines
                    Encoding    = 'UTF8'
                }

                if ($Force.IsPresent) {
                    $AddContentParams.Force = $true
                }

                Add-Content @AddContentParams
                $TotalRowsExported += $CsvLines.Count
                Write-Action1Debug "Appended $($CsvLines.Count) row(s) for vulnerability '$CVEId' to '$ResolvedPath'."
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
