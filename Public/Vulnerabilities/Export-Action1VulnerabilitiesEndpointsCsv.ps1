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
            $orgName = Get-Action1DefaultOrgName
            $orgId = Get-Action1DefaultOrgId
        }

        $normalizedOrgName = ConvertTo-LatinAlphaNumericString -InputString $orgName

        if ([string]::IsNullOrWhiteSpace($normalizedOrgName)) {
            Write-Action1Debug 'Default organization name is empty after normalization.'
            $normalizedOrgName = $orgId
        }

        $timestamp = Get-Date -Format 'yyMMdd_HHmm'
        $fileNameFormat = 'Action1_{0}_VulnerabilitiesEndpoints_{1}.csv'
        $fileName = $fileNameFormat -f $normalizedOrgName, $timestamp
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

# SIG # Begin signature block
# MII9NAYJKoZIhvcNAQcCoII9JTCCPSECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAaCGKjPdvI6YTM
# pK3HV/Embp5r+uVTNoneBSi/fugBtKCCIfYwggXMMIIDtKADAgECAhBUmNLR1FsZ
# lUgTecgRwIeZMA0GCSqGSIb3DQEBDAUAMHcxCzAJBgNVBAYTAlVTMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xSDBGBgNVBAMTP01pY3Jvc29mdCBJZGVu
# dGl0eSBWZXJpZmljYXRpb24gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAy
# MDAeFw0yMDA0MTYxODM2MTZaFw00NTA0MTYxODQ0NDBaMHcxCzAJBgNVBAYTAlVT
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xSDBGBgNVBAMTP01pY3Jv
# c29mdCBJZGVudGl0eSBWZXJpZmljYXRpb24gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRo
# b3JpdHkgMjAyMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALORKgeD
# Bmf9np3gx8C3pOZCBH8Ppttf+9Va10Wg+3cL8IDzpm1aTXlT2KCGhFdFIMeiVPvH
# or+Kx24186IVxC9O40qFlkkN/76Z2BT2vCcH7kKbK/ULkgbk/WkTZaiRcvKYhOuD
# PQ7k13ESSCHLDe32R0m3m/nJxxe2hE//uKya13NnSYXjhr03QNAlhtTetcJtYmrV
# qXi8LW9J+eVsFBT9FMfTZRY33stuvF4pjf1imxUs1gXmuYkyM6Nix9fWUmcIxC70
# ViueC4fM7Ke0pqrrBc0ZV6U6CwQnHJFnni1iLS8evtrAIMsEGcoz+4m+mOJyoHI1
# vnnhnINv5G0Xb5DzPQCGdTiO0OBJmrvb0/gwytVXiGhNctO/bX9x2P29Da6SZEi3
# W295JrXNm5UhhNHvDzI9e1eM80UHTHzgXhgONXaLbZ7LNnSrBfjgc10yVpRnlyUK
# xjU9lJfnwUSLgP3B+PR0GeUw9gb7IVc+BhyLaxWGJ0l7gpPKWeh1R+g/OPTHU3mg
# trTiXFHvvV84wRPmeAyVWi7FQFkozA8kwOy6CXcjmTimthzax7ogttc32H83rwjj
# O3HbbnMbfZlysOSGM1l0tRYAe1BtxoYT2v3EOYI9JACaYNq6lMAFUSw0rFCZE4e7
# swWAsk0wAly4JoNdtGNz764jlU9gKL431VulAgMBAAGjVDBSMA4GA1UdDwEB/wQE
# AwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTIftJqhSobyhmYBAcnz1AQ
# T2ioojAQBgkrBgEEAYI3FQEEAwIBADANBgkqhkiG9w0BAQwFAAOCAgEAr2rd5hnn
# LZRDGU7L6VCVZKUDkQKL4jaAOxWiUsIWGbZqWl10QzD0m/9gdAmxIR6QFm3FJI9c
# Zohj9E/MffISTEAQiwGf2qnIrvKVG8+dBetJPnSgaFvlVixlHIJ+U9pW2UYXeZJF
# xBA2CFIpF8svpvJ+1Gkkih6PsHMNzBxKq7Kq7aeRYwFkIqgyuH4yKLNncy2RtNwx
# AQv3Rwqm8ddK7VZgxCwIo3tAsLx0J1KH1r6I3TeKiW5niB31yV2g/rarOoDXGpc8
# FzYiQR6sTdWD5jw4vU8w6VSp07YEwzJ2YbuwGMUrGLPAgNW3lbBeUU0i/OxYqujY
# lLSlLu2S3ucYfCFX3VVj979tzR/SpncocMfiWzpbCNJbTsgAlrPhgzavhgplXHT2
# 6ux6anSg8Evu75SjrFDyh+3XOjCDyft9V77l4/hByuVkrrOj7FjshZrM77nq81YY
# uVxzmq/FdxeDWds3GhhyVKVB0rYjdaNDmuV3fJZ5t0GNv+zcgKCf0Xd1WF81E+Al
# GmcLfc4l+gcK5GEh2NQc5QfGNpn0ltDGFf5Ozdeui53bFv0ExpK91IjmqaOqu/dk
# ODtfzAzQNb50GQOmxapMomE2gj4d8yu8l13bS3g7LfU772Aj6PXsCyM2la+YZr9T
# 03u4aUoqlmZpxJTG9F9urJh4iIAGXKKy7aIwggaoMIIEkKADAgECAhMzAAMOPcos
# aHEwbiRJAAAAAw49MA0GCSqGSIb3DQEBDAUAMFoxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDUyBBT0MgQ0EgMDMwHhcNMjYwNzEyMTUzNTQ1WhcNMjYwNzE1
# MTUzNTQ1WjBrMQswCQYDVQQGEwJVUzEOMAwGA1UECBMFVGV4YXMxEDAOBgNVBAcT
# B0hvdXN0b24xHDAaBgNVBAoTE0FjdGlvbjEgQ29ycG9yYXRpb24xHDAaBgNVBAMT
# E0FjdGlvbjEgQ29ycG9yYXRpb24wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQCMc+G7Si3EzBhdiFQdI0es+5VzzLP2Ak62ZlvgyNJSBC/Oy7ajVLzvlu6l
# 7LQN2qebsTjm/rYqs4CxiKPjopgGkO8mXdgKfbySk5vZPT/U7hnIrJW+vanvw9na
# yLiXmwN2evYx7i0prhYZPVT9f2afFYzo3Yp/NQO+zlDqfuO/HrSqUMC2KswixNT+
# qB87e6M6EXa6KfMUea1FE/uf/fEeZPnIPCy+0owHFwHl4eEpIFW4qgc+SgJb7EIw
# 2w6NQ9n1aCc0TngrKjDjgSopCh+5v84IKkiIZO0yOGrb3NOxJgWID/BN103Ba3tQ
# 3sTgeahJKkc5rF4BTFxPn0joWndrhOfKOcYD5wKjk5iatvvBpWC/dvUxyZzt0lNj
# 2zuiIPTfUCxOeDGNn5KIIESegANlnnc8FT/iesi9gKBY7d3JjpshbHxvC/dBzRMK
# C3jNsryGpX57+j6XcRlh5gV7dumm+FQLfObK3XZYlwCi461oYWrp0tv2vT+B3aKN
# AfZL/wUCAwEAAaOCAdQwggHQMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeA
# MDsGA1UdJQQ0MDIGCisGAQQBgjdhAQAGCCsGAQUFBwMDBhorBgEEAYI3YYTGyjWC
# 84fIeoPTzfIboMPaLTAdBgNVHQ4EFgQUW5DO3p6kmEH9C/lDtfKnwS3KreIwHwYD
# VR0jBBgwFoAUpEMMf3ZapYXnPo0oDwwXokVpcMYwZwYDVR0fBGAwXjBcoFqgWIZW
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# SUQlMjBWZXJpZmllZCUyMENTJTIwQU9DJTIwQ0ElMjAwMy5jcmwwdAYIKwYBBQUH
# AQEEaDBmMGQGCCsGAQUFBzAChlhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUyMEFPQyUy
# MENBJTIwMDMuY3J0MFQGA1UdIARNMEswSQYEVR0gADBBMD8GCCsGAQUFBwIBFjNo
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5o
# dG0wDQYJKoZIhvcNAQEMBQADggIBAGprK3ztSzvUpmAodkt/G7gVav8fC6kaDp0X
# dUCd3eLY4Wt3wKNoYoNErUeoO9RItC46fznMzKaYu2I3I+/c/8ZiksLJTa0j+EQy
# lj375Ip7DJ/5fZNdeRJQB1N263vW5C+3HOFN9vHR/Fq57TZBCFfTsBX3w0RtpnXj
# 2wgY+1VPVZRDNdwgkutt62wyAR+xftIN0lXUn/6jssHMo/1+B2n/Qbf414pBMRxA
# xXZ3P9pD0vPHz5p9Pg6cyA4TRpDVUUNjEepLLWxtYdjQhe4AqCZO+D/3KKzMD6tG
# iio3Ahl4DPHnk0pOXrdIKmNBfwSuwBi2uJ+DINJA0o5DvB618Eng7tWROlqpD0SP
# LEvk+dKCSKw5UIzwmLu/N4N7rYhGTVLFk9hxiZnolyKvA7ORKdjj9pc4pMKBuUVG
# KHfeBDxGPm+ZRV4S/o/gvA9IMUJ8mMh5lJnbB40ARZVWrNgptwCboDuTWJ4rbJIU
# sM+E2bM/SDDlPirAbZkaIACOi50y+uQSHjaG0RrjxBgXHmFFbwGMyMLKFQv/1y7/
# VFgTOW96jzZ2c9uPWfjre5Gkn3dqYx3bnvV3u+NOGfLeBWCU4KK12GoQQZK/bBxf
# FwUOUkZTyuC4FotXJ8G4KhXEl0SLaVndFtGKtaq1cylcmPf3G+SOFgLD/vLKuRHr
# HIaEhdqkMIIGqDCCBJCgAwIBAgITMwADDj3KLGhxMG4kSQAAAAMOPTANBgkqhkiG
# 9w0BAQwFADBaMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgSUQgVmVyaWZpZWQgQ1MgQU9DIENB
# IDAzMB4XDTI2MDcxMjE1MzU0NVoXDTI2MDcxNTE1MzU0NVowazELMAkGA1UEBhMC
# VVMxDjAMBgNVBAgTBVRleGFzMRAwDgYDVQQHEwdIb3VzdG9uMRwwGgYDVQQKExNB
# Y3Rpb24xIENvcnBvcmF0aW9uMRwwGgYDVQQDExNBY3Rpb24xIENvcnBvcmF0aW9u
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAjHPhu0otxMwYXYhUHSNH
# rPuVc8yz9gJOtmZb4MjSUgQvzsu2o1S875bupey0Ddqnm7E45v62KrOAsYij46KY
# BpDvJl3YCn28kpOb2T0/1O4ZyKyVvr2p78PZ2si4l5sDdnr2Me4tKa4WGT1U/X9m
# nxWM6N2KfzUDvs5Q6n7jvx60qlDAtirMIsTU/qgfO3ujOhF2uinzFHmtRRP7n/3x
# HmT5yDwsvtKMBxcB5eHhKSBVuKoHPkoCW+xCMNsOjUPZ9WgnNE54Kyow44EqKQof
# ub/OCCpIiGTtMjhq29zTsSYFiA/wTddNwWt7UN7E4HmoSSpHOaxeAUxcT59I6Fp3
# a4TnyjnGA+cCo5OYmrb7waVgv3b1Mcmc7dJTY9s7oiD031AsTngxjZ+SiCBEnoAD
# ZZ53PBU/4nrIvYCgWO3dyY6bIWx8bwv3Qc0TCgt4zbK8hqV+e/o+l3EZYeYFe3bp
# pvhUC3zmyt12WJcAouOtaGFq6dLb9r0/gd2ijQH2S/8FAgMBAAGjggHUMIIB0DAM
# BgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDA7BgNVHSUENDAyBgorBgEEAYI3
# YQEABggrBgEFBQcDAwYaKwYBBAGCN2GExso1gvOHyHqD083yG6DD2i0wHQYDVR0O
# BBYEFFuQzt6epJhB/Qv5Q7Xyp8Etyq3iMB8GA1UdIwQYMBaAFKRDDH92WqWF5z6N
# KA8MF6JFaXDGMGcGA1UdHwRgMF4wXKBaoFiGVmh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUy
# MEFPQyUyMENBJTIwMDMuY3JsMHQGCCsGAQUFBwEBBGgwZjBkBggrBgEFBQcwAoZY
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQl
# MjBJRCUyMFZlcmlmaWVkJTIwQ1MlMjBBT0MlMjBDQSUyMDAzLmNydDBUBgNVHSAE
# TTBLMEkGBFUdIAAwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMA0GCSqGSIb3DQEBDAUAA4IC
# AQBqayt87Us71KZgKHZLfxu4FWr/HwupGg6dF3VAnd3i2OFrd8CjaGKDRK1HqDvU
# SLQuOn85zMymmLtiNyPv3P/GYpLCyU2tI/hEMpY9++SKewyf+X2TXXkSUAdTdut7
# 1uQvtxzhTfbx0fxaue02QQhX07AV98NEbaZ149sIGPtVT1WUQzXcIJLrbetsMgEf
# sX7SDdJV1J/+o7LBzKP9fgdp/0G3+NeKQTEcQMV2dz/aQ9Lzx8+afT4OnMgOE0aQ
# 1VFDYxHqSy1sbWHY0IXuAKgmTvg/9yiszA+rRooqNwIZeAzx55NKTl63SCpjQX8E
# rsAYtrifgyDSQNKOQ7wetfBJ4O7VkTpaqQ9EjyxL5PnSgkisOVCM8Ji7vzeDe62I
# Rk1SxZPYcYmZ6JcirwOzkSnY4/aXOKTCgblFRih33gQ8Rj5vmUVeEv6P4LwPSDFC
# fJjIeZSZ2weNAEWVVqzYKbcAm6A7k1ieK2ySFLDPhNmzP0gw5T4qwG2ZGiAAjoud
# MvrkEh42htEa48QYFx5hRW8BjMjCyhUL/9cu/1RYEzlveo82dnPbj1n463uRpJ93
# amMd2571d7vjThny3gVglOCitdhqEEGSv2wcXxcFDlJGU8rguBaLVyfBuCoVxJdE
# i2lZ3RbRirWqtXMpXJj39xvkjhYCw/7yyrkR6xyGhIXapDCCBygwggUQoAMCAQIC
# EzMAAAAYDeuRVamKAJgAAAAAABgwDQYJKoZIhvcNAQEMBQAwYzELMAkGA1UEBhMC
# VVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE0MDIGA1UEAxMrTWlj
# cm9zb2Z0IElEIFZlcmlmaWVkIENvZGUgU2lnbmluZyBQQ0EgMjAyMTAeFw0yNjAz
# MjYxODExMzJaFw0zMTAzMjYxODExMzJaMFoxCzAJBgNVBAYTAlVTMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJRCBW
# ZXJpZmllZCBDUyBBT0MgQ0EgMDMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQDIgNpgNFaiif2VWeWP5I6PnFXxJ/lB37fJR55GCvR7GLZBMkBijbiKVwgp
# BI3xM5nf484znH/qncJ+OCq6y3jgnQW+R8Zd7U+7LjlrmcskalzSQ0ghMxEpnBW8
# /HHs2V8ZJzQk6HP+SDsbvsL7LdlH/eO2l4mknhDBwr0Z/Q966TvEth5b8kCxj1vq
# iV4YNthLGRqZR9u2fK/yBMWu83p6O4uo2Edg++gEew5IL7vnnnKFqmSh/R9vPJy3
# WF1YcZewAUx8sXZNUnx3ZhVg59l2LpitPiwzE6FMqIsqaEvVe3MzuFd2a/uWDZH6
# VbDyUiRK78mIg1DQYA9zDEyyBFcNI+nxVSzglvL6u7PRuNqgcV3sf6ELxw89ysQM
# /Z4R1hRFWXRpyOWKKAKtfBHTk0UnNiPcxmLMMYs8jeUjOidfVPjTIry/UVwnwxdl
# kK85cZfBEMYZ/DBNOwdomP459Y1n8izKkbhsa+p4lw+cQVxATBFx9ggR79HhryT7
# HDmpPLvkJvBZ4wW4CW32UT2SMyDe28nIOU3m+hfHlVeKcLBQcym5VoRDjIcCVI7u
# qgGW2PNME0cfei8zCwCy6HCsssJWFS7eg/YbFhnATJcyWfMrkNuAbMfMN8Npg8cr
# S6jVVowyD0GG5zdgi+uQVcSK/638mA1xEYK3pnIoQgO09uuDBwIDAQABo4IB3DCC
# AdgwDgYDVR0PAQH/BAQDAgGGMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBSk
# Qwx/dlqlhec+jSgPDBeiRWlwxjBUBgNVHSAETTBLMEkGBFUdIAAwQTA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9z
# aXRvcnkuaHRtMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMBIGA1UdEwEB/wQI
# MAYBAf8CAQAwHwYDVR0jBBgwFoAU2UEpsA8PY2zvadf1zSmepEhqMOYwcAYDVR0f
# BGkwZzBloGOgYYZfaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwv
# TWljcm9zb2Z0JTIwSUQlMjBWZXJpZmllZCUyMENvZGUlMjBTaWduaW5nJTIwUENB
# JTIwMjAyMS5jcmwwfQYIKwYBBQUHAQEEcTBvMG0GCCsGAQUFBzAChmFodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIw
# VmVyaWZpZWQlMjBDb2RlJTIwU2lnbmluZyUyMFBDQSUyMDIwMjEuY3J0MA0GCSqG
# SIb3DQEBDAUAA4ICAQBxxyBW+X6mhdRiSwD9PMMWcGUAnx5/QUwnNvZdFGEX+4DR
# DIr9WCh4C87wHtw+lg1D3uzK10DstPX0LFLBFAC3vWMYX4ImXwoLhoR0xlN8mUdo
# rJ3bgnpCJWuI1531Z1rCwPuUrSkBxfOIGDk3p2ECb3Ho/xHi5PRSR/OUrWuQHwXi
# aXMTuXu3IRLezwVkZpFmNwYRD57R9Nx2F/yM7tzOY0Hh0hGCaYEK38/6FrS0SXad
# XWyDUCfn5XOGACRjUCnHx+JQUG0f4SHD+iblpAI0gl+ZHnVmdXXxHTZeTa0CYCIh
# FxKP2922s0g6zLmeiV13LWUmtt/UF7TrWXpMi2/0UNniaDoH7rnPGRV5xVX8uXy4
# sZii4aswzqPM7Y7+mzcranqZ8EjZk5gjLhQ3A2sZaprlOu8CaRmyfcIiVH7zVfgA
# vm81MWXFziAf7my7QOvnyEFPGddq8MSfPtfRyw/Uq3uH6KpoaJNIfPYH6fceZSi5
# 3Rat1A9grExq3ROjhhSpTcchuBItAMNVPxoKNbUm+iR/X3XkL+9WQginjyHe+hXL
# clY8vAGXFD1p40PqMIpAYsmEJBFKW9df4//1N5oQDr/FY9IBJl/oSS979i5rtT7N
# Zz9KvYraCPRBGs0QCy+sWvgQa0coM70QJVLeVwmSxUO/0od0w9Qry7bSLrxGoDCC
# B54wggWGoAMCAQICEzMAAAAHh6M0o3uljhwAAAAAAAcwDQYJKoZIhvcNAQEMBQAw
# dzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjFI
# MEYGA1UEAxM/TWljcm9zb2Z0IElkZW50aXR5IFZlcmlmaWNhdGlvbiBSb290IENl
# cnRpZmljYXRlIEF1dGhvcml0eSAyMDIwMB4XDTIxMDQwMTIwMDUyMFoXDTM2MDQw
# MTIwMTUyMFowYzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjE0MDIGA1UEAxMrTWljcm9zb2Z0IElEIFZlcmlmaWVkIENvZGUgU2ln
# bmluZyBQQ0EgMjAyMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALLw
# wK8ZiCji3VR6TElsaQhVCbRS/3pK+MHrJSj3Zxd3KU3rlfL3qrZilYKJNqztA9OQ
# acr1AwoNcHbKBLbsQAhBnIB34zxf52bDpIO3NJlfIaTE/xrweLoQ71lzCHkD7A4A
# s1Bs076Iu+mA6cQzsYYH/Cbl1icwQ6C65rU4V9NQhNUwgrx9rGQ//h890Q8JdjLL
# w0nV+ayQ2Fbkd242o9kH82RZsH3HEyqjAB5a8+Ae2nPIPc8sZU6ZE7iRrRZywRmr
# KDp5+TcmJX9MRff241UaOBs4NmHOyke8oU1TYrkxh+YeHgfWo5tTgkoSMoayqoDp
# HOLJs+qG8Tvh8SnifW2Jj3+ii11TS8/FGngEaNAWrbyfNrC69oKpRQXY9bGH6jn9
# NEJv9weFxhTwyvx9OJLXmRGbAUXN1U9nf4lXezky6Uh/cgjkVd6CGUAf0K+Jw+GE
# /5VpIVbcNr9rNE50Sbmy/4RTCEGvOq3GhjITbCa4crCzTTHgYYjHs1NbOc6brH+e
# KpWLtr+bGecy9CrwQyx7S/BfYJ+ozst7+yZtG2wR461uckFu0t+gCwLdN0A6cFtS
# RtR8bvxVFyWwTtgMMFRuBa3vmUOTnfKLsLefRaQcVTgRnzeLzdpt32cdYKp+dhr2
# ogc+qM6K4CBI5/j4VFyC4QFeUP2YAidLtvpXRRo3AgMBAAGjggI1MIICMTAOBgNV
# HQ8BAf8EBAMCAYYwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNlBKbAPD2Ns
# 72nX9c0pnqRIajDmMFQGA1UdIARNMEswSQYEVR0gADBBMD8GCCsGAQUFBwIBFjNo
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5o
# dG0wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDwYDVR0TAQH/BAUwAwEB/zAf
# BgNVHSMEGDAWgBTIftJqhSobyhmYBAcnz1AQT2ioojCBhAYDVR0fBH0wezB5oHeg
# dYZzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0
# JTIwSWRlbnRpdHklMjBWZXJpZmljYXRpb24lMjBSb290JTIwQ2VydGlmaWNhdGUl
# MjBBdXRob3JpdHklMjAyMDIwLmNybDCBwwYIKwYBBQUHAQEEgbYwgbMwgYEGCCsG
# AQUFBzAChnVodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01p
# Y3Jvc29mdCUyMElkZW50aXR5JTIwVmVyaWZpY2F0aW9uJTIwUm9vdCUyMENlcnRp
# ZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAyMC5jcnQwLQYIKwYBBQUHMAGGIWh0dHA6
# Ly9vbmVvY3NwLm1pY3Jvc29mdC5jb20vb2NzcDANBgkqhkiG9w0BAQwFAAOCAgEA
# fyUqnv7Uq+rdZgrbVyNMul5skONbhls5fccPlmIbzi+OwVdPQ4H55v7VOInnmezQ
# EeW4LqK0wja+fBznANbXLB0KrdMCbHQpbLvG6UA/Xv2pfpVIE1CRFfNF4XKO8XYE
# a3oW8oVH+KZHgIQRIwAbyFKQ9iyj4aOWeAzwk+f9E5StNp5T8FG7/VEURIVWArbA
# zPt9ThVN3w1fAZkF7+YU9kbq1bCR2YD+MtunSQ1Rft6XG7b4e0ejRA7mB2IoX5hN
# h3UEauY0byxNRG+fT2MCEhQl9g2i2fs6VOG19CNep7SquKaBjhWmirYyANb0RJSL
# WjinMLXNOAga10n8i9jqeprzSMU5ODmrMCJE12xS/NWShg/tuLjAsKP6SzYZ+1Ry
# 358ZTFcx0FS/mx2vSoU8s8HRvy+rnXqyUJ9HBqS0DErVLjQwK8VtsBdekBmdTbQV
# oCgPCqr+PDPB3xajYnzevs7eidBsM71PINK2BoE2UfMwxCCX3mccFgx6UsQeRSdV
# VVNSyALQe6PT12418xon2iDGE81OGCreLzDcMAZnrUAx4XQLUz6ZTl65yPUiOh3k
# 7Yww94lDf+8oG2oZmDh5O1Qe38E+M3vhKwmzIeoB1dVLlz4i3IpaDcR+iuGjH2Td
# aC1ZOmBXiCRKJLj4DT2uhJ04ji+tHD6n58vhavFIrmcxghqUMIIakAIBATBxMFox
# CzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzAp
# BgNVBAMTIk1pY3Jvc29mdCBJRCBWZXJpZmllZCBDUyBBT0MgQ0EgMDMCEzMAAw49
# yixocTBuJEkAAAADDj0wDQYJYIZIAWUDBAIBBQCgXjAQBgorBgEEAYI3AgEMMQIw
# ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAvBgkqhkiG9w0BCQQxIgQgstSZ
# CKdRUuaMlUjxqR5Rki5MgwSenh6ynqa1HGs18hIwDQYJKoZIhvcNAQEBBQAEggGA
# IuUzIuiO7fgthF06K/XQQVyJf1OvM/4ehH4BgW6ZBXUah5k6aI3nZlJkuJgcDK3i
# izmE3AHYMx4pBkZ278GnoC225cjmwgfDcZ1dWLEjVY3JumVY1xv9a251xqGJ9C02
# MrzoysQf65w9SG2EeJZ+EqZWsWO+tEUdlGkFZuTbw4bb/9A471dwp1J6hYxz2u1M
# PT8jK/DqVTQiDsnksBZ8mb1yMJhGbMhMxz95SBGs5uoX2n6txE9nARoKfz/aIWdD
# W7o2JY5cNd93IrE26V/wPd7PxbMm6De/kc1rMZiFEJlpQUropHciFK1/JjflavxV
# iTyFUsiB5Qh+Ek7bxjECWG2jEoURsRBBhT2bJaCnKhkhY8UKkVQmYftqcOgAKLZn
# QAcRNArZ4yWMrTW+4jXNOrzxlNQ0llkbnILMLZ+N2gMleU6SsYZXoxIUdgjsgJc8
# XGjzUrKb9y/zpkH0PtduUPXm6XS+RBHbb7YuffsvQIY+jHTFy4gnVSkCxEoQKv+N
# oYIYFDCCGBAGCisGAQQBgjcDAwExghgAMIIX/AYJKoZIhvcNAQcCoIIX7TCCF+kC
# AQMxDzANBglghkgBZQMEAgEFADCCAWIGCyqGSIb3DQEJEAEEoIIBUQSCAU0wggFJ
# AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIA0LvkcwZ8nctvKo8uDu
# svz5x9k138aPHXpC9SgxGnLUAgZqT9WFMT4YEzIwMjYwNzE0MTIzOTQ2LjI5OVow
# BIACAfSggeGkgd4wgdsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNV
# BAsTHm5TaGllbGQgVFNTIEVTTjpBNTAwLTA1RTAtRDk0NzE1MDMGA1UEAxMsTWlj
# cm9zb2Z0IFB1YmxpYyBSU0EgVGltZSBTdGFtcGluZyBBdXRob3JpdHmggg8hMIIH
# gjCCBWqgAwIBAgITMwAAAAXlzw//Zi7JhwAAAAAABTANBgkqhkiG9w0BAQwFADB3
# MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMUgw
# RgYDVQQDEz9NaWNyb3NvZnQgSWRlbnRpdHkgVmVyaWZpY2F0aW9uIFJvb3QgQ2Vy
# dGlmaWNhdGUgQXV0aG9yaXR5IDIwMjAwHhcNMjAxMTE5MjAzMjMxWhcNMzUxMTE5
# MjA0MjMxWjBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBp
# bmcgQ0EgMjAyMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJ5851Jj
# /eDFnwV9Y7UGIqMcHtfnlzPREwW9ZUZHd5HBXXBvf7KrQ5cMSqFSHGqg2/qJhYqO
# QxwuEQXG8kB41wsDJP5d0zmLYKAY8Zxv3lYkuLDsfMuIEqvGYOPURAH+Ybl4SJEE
# Snt0MbPEoKdNihwM5xGv0rGofJ1qOYSTNcc55EbBT7uq3wx3mXhtVmtcCEr5ZKTk
# KKE1CxZvNPWdGWJUPC6e4uRfWHIhZcgCsJ+sozf5EeH5KrlFnxpjKKTavwfFP6Xa
# GZGWUG8TZaiTogRoAlqcevbiqioUz1Yt4FRK53P6ovnUfANjIgM9JDdJ4e0qiDRm
# 5sOTiEQtBLGd9Vhd1MadxoGcHrRCsS5rO9yhv2fjJHrmlQ0EIXmp4DhDBieKUGR+
# eZ4CNE3ctW4uvSDQVeSp9h1SaPV8UWEfyTxgGjOsRpeexIveR1MPTVf7gt8hY64X
# NPO6iyUGsEgt8c2PxF87E+CO7A28TpjNq5eLiiunhKbq0XbjkNoU5JhtYUrlmAbp
# xRjb9tSreDdtACpm3rkpxp7AQndnI0Shu/fk1/rE3oWsDqMX3jjv40e8KN5YsJBn
# czyWB4JyeeFMW3JBfdeAKhzohFe8U5w9WuvcP1E8cIxLoKSDzCCBOu0hWdjzKNu8
# Y5SwB1lt5dQhABYyzR3dxEO/T1K/BVF3rV69AgMBAAGjggIbMIICFzAOBgNVHQ8B
# Af8EBAMCAYYwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFGtpKDo1L0hjQM97
# 2K9J6T7ZPdshMFQGA1UdIARNMEswSQYEVR0gADBBMD8GCCsGAQUFBwIBFjNodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0w
# EwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEw
# DwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTIftJqhSobyhmYBAcnz1AQT2io
# ojCBhAYDVR0fBH0wezB5oHegdYZzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jcmwvTWljcm9zb2Z0JTIwSWRlbnRpdHklMjBWZXJpZmljYXRpb24lMjBS
# b290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDIwLmNybDCBlAYIKwYB
# BQUHAQEEgYcwgYQwgYEGCCsGAQUFBzAChnVodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMElkZW50aXR5JTIwVmVyaWZpY2F0
# aW9uJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAyMC5jcnQw
# DQYJKoZIhvcNAQEMBQADggIBAF+Idsd+bbVaFXXnTHho+k7h2ESZJRWluLE0Oa/p
# O+4ge/XEizXvhs0Y7+KVYyb4nHlugBesnFqBGEdC2IWmtKMyS1OWIviwpnK3aL5J
# edwzbeBF7POyg6IGG/XhhJ3UqWeWTO+Czb1c2NP5zyEh89F72u9UIw+IfvM9lzDm
# c2O2END7MPnrcjWdQnrLn1Ntday7JSyrDvBdmgbNnCKNZPmhzoa8PccOiQljjTW6
# GePe5sGFuRHzdFt8y+bN2neF7Zu8hTO1I64XNGqst8S+w+RUdie8fXC1jKu3m9KG
# IqF4aldrYBamyh3g4nJPj/LR2CBaLyD+2BuGZCVmoNR/dSpRCxlot0i79dKOChmo
# ONqbMI8m04uLaEHAv4qwKHQ1vBzbV/nG89LDKbRSSvijmwJwxRxLLpMQ/u4xXxFf
# R4f/gksSkbJp7oqLwliDm/h+w0aJ/U5ccnYhYb7vPKNMN+SZDWycU5ODIRfyoGl5
# 9BsXR/HpRGtiJquOYGmvA/pk5vC1lcnbeMrcWD/26ozePQ/TWfNXKBOmkFpvPE8C
# H+EeGGWzqTCjdAsno2jzTeNSxlx3glDGJgcdz5D/AAxw9Sdgq/+rY7jjgs7X6fqP
# TXPmaCAJKVHAP19oEjJIBwD1LyHbaEgBxFCogYSOiUIr0Xqcr1nJfiWG2GwYe6Zo
# AF1bMIIHlzCCBX+gAwIBAgITMwAAAFZ+j51YCI7pYAAAAAAAVjANBgkqhkiG9w0B
# AQwFADBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcg
# Q0EgMjAyMDAeFw0yNTEwMjMyMDQ2NTFaFw0yNjEwMjIyMDQ2NTFaMIHbMQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3Nv
# ZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046
# QTUwMC0wNUUwLUQ5NDcxNTAzBgNVBAMTLE1pY3Jvc29mdCBQdWJsaWMgUlNBIFRp
# bWUgU3RhbXBpbmcgQXV0aG9yaXR5MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAtKWfm/ul027/d8Rlb8Mn/g0QUvvLqY2Vsy3tI8U2tFSspTZomZOD3BHT
# 8LkR+RrhMJgb1VjAKFNysaK9cLSXifPGSIBrPCgs9P4y24lrJEmrV6Q5z4BmqMhI
# PrZhEvZnWpCS4HO7jYSei/nxmC7/1Er+l5Lg3PmSxb8d2IVcARxSw1B4mxB6XI0n
# kel9wa1dYb2wfGpofraFmxZOxT9eNht4LH0RBSVueba6ZNpjS/0gtfm7qiIiyP6p
# 6PRzTTbMnVqsHnV/d/rW0zHx+Q+QNZ5wUqKmTZJB9hU853+2pX5rDfK32uNY9/WB
# OAmzbqgpEdQkbiMavUMyUDShmycIvgHdQnS207sTj8M+kJL3tOdahPuPqMwsaCCg
# dfwwQx0O9TKe7FSvbAEYs1AnldCl/KHGZCOVvUNqjyL10JLe0/+GD9/ynqXGWFpX
# OjaunvZ/cKROhjN4M5e6xx0b2miqcPii4/ii2ZheKallJET7CKlpFShs3wyg6F/f
# ojQxQvPnbWD4Nyx6lhjWjwmoLcx6w1FSCtavLCly33BLRSlTU4qKUxaa8d7YN7Eq
# pn9XO0SY0umOvKFXrWH7rxl+9iaicitdnTTksAnRjvekdKT3lg7lRMfmfZU8vXNi
# N0UYJzT9EjqjRm0uN/h0oXxPhNfPYqeFbyPXGGxzaYUz6zx3qTcCAwEAAaOCAcsw
# ggHHMB0GA1UdDgQWBBS+tjPyu6tZ/h5GsyLvyz1H+FNIWjAfBgNVHSMEGDAWgBRr
# aSg6NS9IY0DPe9ivSek+2T3bITBsBgNVHR8EZTBjMGGgX6BdhltodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBQdWJsaWMlMjBS
# U0ElMjBUaW1lc3RhbXBpbmclMjBDQSUyMDIwMjAuY3JsMHkGCCsGAQUFBwEBBG0w
# azBpBggrBgEFBQcwAoZdaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# ZXJ0cy9NaWNyb3NvZnQlMjBQdWJsaWMlMjBSU0ElMjBUaW1lc3RhbXBpbmclMjBD
# QSUyMDIwMjAuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUH
# AwgwDgYDVR0PAQH/BAQDAgeAMGYGA1UdIARfMF0wUQYMKwYBBAGCN0yDfQEBMEEw
# PwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9j
# cy9SZXBvc2l0b3J5Lmh0bTAIBgZngQwBBAIwDQYJKoZIhvcNAQEMBQADggIBAA4D
# qAXEsO26j/La7Fgn/Qifit8xuZekqZ57+Ye+sH/hRTbEEjGYrZgsqwR/lUUfKCFp
# bZF8msaZPQJOR4YYUEU8XyjLrn8Y1jCSmoxh9l7tWiSoc/JFBw356JAmzGGxeBA2
# EWSxRuTr1AuZe6nYaN8/wtFkiHcs8gMadxXBs6DxVhyu5YnhLPQkfumKm3lFftwE
# 7pieV7f1lskmlgsC6AeSGCzGPZUgCvcH5Tv/Qe9z7bIImSD3SuzhOIwaP+eKQTYf
# 67TifyJKkWQSdGfTA6Kcu41k8LB6oPK+MLk1jbxxK5wPqLSL62xjK04SBXHEJSEn
# sFt0zxWkxP/lgej1DxqUnmrYEdkxvzKSHIAqFWSZul/5hI+vJxvFPhsNQBEk4cSu
# lDkJQpcdVi/gmf/mHFOYhDBjsa15s4L+2sBil3XV/T8RiR66Q8xYvTLRWxd2dVsr
# OoCwnsU4WIeiC0JinCv1WLHEh7Qyzr9RSr4kKJLWdpNYLhgjkojTmEkAjFO774t3
# xB7enbvIF0GOsV19xnCUzq9EGKyt0gMuaphKlNjJ+aTpjWMZDGo+GOKsnp93Hmft
# ml0Syp3F9+M3y+y6WJGUZoIZJq227jDjjEndtpUrh9BdPdVIfVJD/Au81Rzh05UH
# AivorQ3Os8PELHIgiOd9TWzbdgmGzcILt/ddVQERMYIHRjCCB0ICAQEweDBhMQsw
# CQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYD
# VQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMAIT
# MwAAAFZ+j51YCI7pYAAAAAAAVjANBglghkgBZQMEAgEFAKCCBJ8wEQYLKoZIhvcN
# AQkQAg8xAgUAMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0B
# CQUxDxcNMjYwNzE0MTIzOTQ2WjAvBgkqhkiG9w0BCQQxIgQgBzITMAeaqO/8BSYK
# 9Xnc2cUNdVyHaDkluUpapfBgkJgwgbkGCyqGSIb3DQEJEAIvMYGpMIGmMIGjMIGg
# BCC2DDMlTaTj8JV3iTg5Xnpe4CSH60143Z+X9o5NBgMMqDB8MGWkYzBhMQswCQYD
# VQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQD
# EylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMAITMwAA
# AFZ+j51YCI7pYAAAAAAAVjCCA2EGCyqGSIb3DQEJEAISMYIDUDCCA0yhggNIMIID
# RDCCAiwCAQEwggEJoYHhpIHeMIHbMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046QTUwMC0wNUUwLUQ5NDcxNTAzBgNV
# BAMTLE1pY3Jvc29mdCBQdWJsaWMgUlNBIFRpbWUgU3RhbXBpbmcgQXV0aG9yaXR5
# oiMKAQEwBwYFKw4DAhoDFQD/c/cpFSqQWYBeXggyRJ2ZbvYEEaBnMGWkYzBhMQsw
# CQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYD
# VQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMDAN
# BgkqhkiG9w0BAQsFAAIFAO4AQsAwIhgPMjAyNjA3MTQwNTA4MTZaGA8yMDI2MDcx
# NTA1MDgxNlowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA7gBCwAIBADAKAgEAAgIa
# LgIB/zAHAgEAAgISyDAKAgUA7gGUQAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgor
# BgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBCwUA
# A4IBAQBawNiAu19P8UMdHtMKAdpabLCalRZ7uOxQ+2AYTVUwA1EUZhNzrIafj4RB
# 3fZ+d+Rv41nou+vDQSexdB3YTh9HOxI6aRNAZebyVIbmM0aEPyXMJWkr5JuuTRP5
# WidtJLpunz9RmQgKN+yrxxkHI0pRAJpKMquMItY8UO9WxWzbvw6LS+Js+Phb15Oc
# cQZHH1VEtEZvfNKOTi1qv/ukI01x2Oe/sNnaRB9m/oCplYOwS1oDFa41w+f0U8uz
# rJgkhr5I+L00iSdIHyLBH3RKEDi9oTDmTg4es9jcgUE7XZU4ah61y1o6QxOZyZ/S
# jsXtCttIDzXwzZc9imcBpATc9y4XMA0GCSqGSIb3DQEBAQUABIICAH53OSJE5RQu
# CtryDd5R0pL64hUtJwO5KK6V3HFpRnUSLRMhgk7VSkkBhbi1YLBHdph1xFf9qVfx
# HtRNyT9FiBJO1fdfIUKHbfUT6J6WUcyZoEaEJ48GypvfJLFdELmGdY0fDmedw7pL
# gZzDEBberd9rTFuHkm+NwJxKVH6xcNMo893ZiX/yrf1hv04zGFYavJQxEMqnICvv
# zo9sL33HhWC1QiDeOxNPhIjk/PlaGgMGBz2G+Z6ToDzzCYX15iqfkBOC6mLk8tuy
# IJ98RmF4483gwtHFJM8FJaYFOG1GTOu30HVQ4FKD7jaEfcMHMutSHRHkZvK/48A9
# X7kjQQJc+5lHsL3qsP4+8P3nlDnFnrVo1Muy+CUxjI/nZXhD1MrF8dVuw4UVL8Zq
# w9eMLZMKlV6Uu5IXDzvuTgXqYpb9UmEAwuyrymo8whpIEMS/i4920J27LlMJBIul
# BtvDZim8JBLmmKMJ/ZxAQueRpzm6HnFCvubkw90n6ZTk/Wy5sOAbgHpcXfB0A94i
# LoJnp8bizKcJ0MGDMFfTS2hYeduam2yD9jNdGGaiH8wEq11H0AZIlcAFHFGLp5v9
# Qxf04YChVSyaPBn0ygdaCdl3GPnMPT1OffUdZR1wN9Ih4V5zo1fFX0kbm85qdrxy
# bk22aPYIweA9wJ98Pd+XO0QeRLWl9+iW
# SIG # End signature block
