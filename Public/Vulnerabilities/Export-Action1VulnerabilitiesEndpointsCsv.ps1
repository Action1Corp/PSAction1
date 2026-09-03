# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Export-Action1VulnerabilitiesEndpointsCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^CVE-\d{4}-\d{4,}$')]
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

        $fileNameFormat = $Script:Action1_VulnerabilitiesEndpointsExportFileNameTemplate `
         -f $normalizedOrgName, '{0}'
        $fileName = New-ExportFileName `
            -FileNameFormat $fileNameFormat `
            -TimestampTemplate $Script:Action1_ExportFileNameTimestampTemplate
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA4Pl0AMvSjPndu
# pLYOHMu5KPWmaYkskd4Z2HD/hRrcN6CCIfYwggXMMIIDtKADAgECAhBUmNLR1FsZ
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
# 03u4aUoqlmZpxJTG9F9urJh4iIAGXKKy7aIwggaoMIIEkKADAgECAhMzAAVQb+ul
# g6yVQBN8AAAABVBvMA0GCSqGSIb3DQEBDAUAMFoxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDUyBFT0MgQ0EgMDQwHhcNMjYwOTAxMjEzMTE4WhcNMjYwOTA0
# MjEzMTE4WjBrMQswCQYDVQQGEwJVUzEOMAwGA1UECBMFVGV4YXMxEDAOBgNVBAcT
# B0hvdXN0b24xHDAaBgNVBAoTE0FjdGlvbjEgQ29ycG9yYXRpb24xHDAaBgNVBAMT
# E0FjdGlvbjEgQ29ycG9yYXRpb24wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQCJylJmhQ0cw95RaY8c4fpGK2g3SaWd5eS1bebgehM12hPp3gVe8isRkPbG
# yg+CKG9e6fzg1I0pVajjYpnxD1Dol2NBzw6aABrAcS3VsxDey5Uf8W4efVZi+uwc
# 7c3ZDO3nqqsPehTpvWNQv7XjCf1Lsax7VV6wbBXx6EHB7JNx+tsYsAynwrZrepiJ
# wQSC4qiGOVs0+yRf0Ag2cvcr+9SemM5yBE1R2t3b/O1qwuxmcHQoqkAbUX/1R+ub
# YUhptnEKxuZ7dF18GDJ49p9VpCkRWd+/n0WZKsdtqrSOxYbRarkx+kK9YLZuOxnR
# ygx8Y34rZ9j4Xgrq4JIbqcW2norz7xUrhH8T7s79Km+KmaD2SeiahuNg9k0eIsO0
# xoJs5f7rvKTkANM2eYo14/l7mdCHb6sWQgmn0kyfTj9aBBGp8f/1IACn8HjV7vMM
# /TBQ063+gGLKapoFeHlykVr4bBBOacFk3LD0hmIgL0WuLUmwadrL/6OhezqVUTqm
# uNQRnjsCAwEAAaOCAdQwggHQMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeA
# MDsGA1UdJQQ0MDIGCisGAQQBgjdhAQAGCCsGAQUFBwMDBhorBgEEAYI3YYTGyjWC
# 84fIeoPTzfIboMPaLTAdBgNVHQ4EFgQU23a3o7ti8LJ64qJLGpA2bUP7kWgwHwYD
# VR0jBBgwFoAUmvFUd3UMhxY3RqCs3nn59H/BeOkwZwYDVR0fBGAwXjBcoFqgWIZW
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# SUQlMjBWZXJpZmllZCUyMENTJTIwRU9DJTIwQ0ElMjAwNC5jcmwwdAYIKwYBBQUH
# AQEEaDBmMGQGCCsGAQUFBzAChlhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUyMEVPQyUy
# MENBJTIwMDQuY3J0MFQGA1UdIARNMEswSQYEVR0gADBBMD8GCCsGAQUFBwIBFjNo
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5o
# dG0wDQYJKoZIhvcNAQEMBQADggIBAEGehXcmuYx33hAQpQt9f1wjt8JleosMmtmh
# XE8Nb+cm8X2yIEMSCqK4nU14caz04MMv20+/OaZvfXCXf6Mi/qH7PnM2R9UOrgXs
# qqmxxm/Ur11xiQJX6Q+BGepkMTTZG9C4EWR6sbJVXEssglOo6B0qkizP0lgi8GHP
# Rv33IGgV9fOE5epolH6Aw+DH4hdpJQ1SL3n/Cc2A9pyY7gJ/jK5rg65df8ZGid//
# jWqJ8L2hWR/VzweWIZKVWCGH8j+I2XwTQzqOdY7zCtl18iMLv7v5kJOtqQAjZeE0
# 0MlZyvRcOSOuoV1FCrtySWV9nGZTIHCRLcYhsAJzA/N87uUJHp1GE/eXgGmf75Vm
# aJw2oCHJsHwpt9E4r+XMZHXp7VM1oJOyaTXPgIJapUSAAgHXLlsHMBqMJn+PtXN0
# SvO7KG9NY48KQUigZt4AalRa0lJkAy16I3DCDcKCgUtQQIbviIa6URJSxgOfmjUl
# xmWslM03qED77XN8quQHnIl3q1Ov82iK4CR9NrRo0zaU/svdmJ5eufCiXkWiNL5H
# rSNaY85u74fSNVhNZVVWV/rB3dbSI4Hu9wvmUmKYbuu7EKI4WQdGOMSYwaWCkmuB
# HP9VguTV9KkU0WAG4FqAWlMIHMvRv+2lSZZ052RxLgET+ev1hNoRjwHRR0vNTOWx
# l7ld33OuMIIGqDCCBJCgAwIBAgITMwAFUG/rpYOslUATfAAAAAVQbzANBgkqhkiG
# 9w0BAQwFADBaMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgSUQgVmVyaWZpZWQgQ1MgRU9DIENB
# IDA0MB4XDTI2MDkwMTIxMzExOFoXDTI2MDkwNDIxMzExOFowazELMAkGA1UEBhMC
# VVMxDjAMBgNVBAgTBVRleGFzMRAwDgYDVQQHEwdIb3VzdG9uMRwwGgYDVQQKExNB
# Y3Rpb24xIENvcnBvcmF0aW9uMRwwGgYDVQQDExNBY3Rpb24xIENvcnBvcmF0aW9u
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAicpSZoUNHMPeUWmPHOH6
# RitoN0mlneXktW3m4HoTNdoT6d4FXvIrEZD2xsoPgihvXun84NSNKVWo42KZ8Q9Q
# 6JdjQc8OmgAawHEt1bMQ3suVH/FuHn1WYvrsHO3N2Qzt56qrD3oU6b1jUL+14wn9
# S7Gse1VesGwV8ehBweyTcfrbGLAMp8K2a3qYicEEguKohjlbNPskX9AINnL3K/vU
# npjOcgRNUdrd2/ztasLsZnB0KKpAG1F/9Ufrm2FIabZxCsbme3RdfBgyePafVaQp
# EVnfv59FmSrHbaq0jsWG0Wq5MfpCvWC2bjsZ0coMfGN+K2fY+F4K6uCSG6nFtp6K
# 8+8VK4R/E+7O/Spvipmg9knomobjYPZNHiLDtMaCbOX+67yk5ADTNnmKNeP5e5nQ
# h2+rFkIJp9JMn04/WgQRqfH/9SAAp/B41e7zDP0wUNOt/oBiymqaBXh5cpFa+GwQ
# TmnBZNyw9IZiIC9Fri1JsGnay/+joXs6lVE6prjUEZ47AgMBAAGjggHUMIIB0DAM
# BgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDA7BgNVHSUENDAyBgorBgEEAYI3
# YQEABggrBgEFBQcDAwYaKwYBBAGCN2GExso1gvOHyHqD083yG6DD2i0wHQYDVR0O
# BBYEFNt2t6O7YvCyeuKiSxqQNm1D+5FoMB8GA1UdIwQYMBaAFJrxVHd1DIcWN0ag
# rN55+fR/wXjpMGcGA1UdHwRgMF4wXKBaoFiGVmh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUy
# MEVPQyUyMENBJTIwMDQuY3JsMHQGCCsGAQUFBwEBBGgwZjBkBggrBgEFBQcwAoZY
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQl
# MjBJRCUyMFZlcmlmaWVkJTIwQ1MlMjBFT0MlMjBDQSUyMDA0LmNydDBUBgNVHSAE
# TTBLMEkGBFUdIAAwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMA0GCSqGSIb3DQEBDAUAA4IC
# AQBBnoV3JrmMd94QEKULfX9cI7fCZXqLDJrZoVxPDW/nJvF9siBDEgqiuJ1NeHGs
# 9ODDL9tPvzmmb31wl3+jIv6h+z5zNkfVDq4F7KqpscZv1K9dcYkCV+kPgRnqZDE0
# 2RvQuBFkerGyVVxLLIJTqOgdKpIsz9JYIvBhz0b99yBoFfXzhOXqaJR+gMPgx+IX
# aSUNUi95/wnNgPacmO4Cf4yua4OuXX/GRonf/41qifC9oVkf1c8HliGSlVghh/I/
# iNl8E0M6jnWO8wrZdfIjC7+7+ZCTrakAI2XhNNDJWcr0XDkjrqFdRQq7ckllfZxm
# UyBwkS3GIbACcwPzfO7lCR6dRhP3l4Bpn++VZmicNqAhybB8KbfROK/lzGR16e1T
# NaCTsmk1z4CCWqVEgAIB1y5bBzAajCZ/j7VzdErzuyhvTWOPCkFIoGbeAGpUWtJS
# ZAMteiNwwg3CgoFLUECG74iGulESUsYDn5o1JcZlrJTNN6hA++1zfKrkB5yJd6tT
# r/NoiuAkfTa0aNM2lP7L3ZieXrnwol5FojS+R60jWmPObu+H0jVYTWVVVlf6wd3W
# 0iOB7vcL5lJimG7ruxCiOFkHRjjEmMGlgpJrgRz/VYLk1fSpFNFgBuBagFpTCBzL
# 0b/tpUmWdOdkcS4BE/nr9YTaEY8B0UdLzUzlsZe5Xd9zrjCCBygwggUQoAMCAQIC
# EzMAAAAXJ0UJC4uHr8YAAAAAABcwDQYJKoZIhvcNAQEMBQAwYzELMAkGA1UEBhMC
# VVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE0MDIGA1UEAxMrTWlj
# cm9zb2Z0IElEIFZlcmlmaWVkIENvZGUgU2lnbmluZyBQQ0EgMjAyMTAeFw0yNjAz
# MjYxODExMzFaFw0zMTAzMjYxODExMzFaMFoxCzAJBgNVBAYTAlVTMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJRCBW
# ZXJpZmllZCBDUyBFT0MgQ0EgMDQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQCCx2T+Aw9mKgGVzJ+Tq0PMn49G3itIsYpbx7ClLSRHFe1RELdPcZ1sIqWO
# hsSfy6yyqEapClGH9Je9FXA1cQgZvvpQbkg+QInVLr/0EPrVBCwrM96lbRI2PxNe
# CwXG9LsyW2hG6KQgintDmNCBo4zpDIr377plVdSliZm6UB7rHwmvBnR02QT6tnrq
# Wq2ihzB6lRJVTEzuh0OafzIMeMnYM0+x+ve5EOLHdfiq+HXiMf9Jb7YLHtYgyHIi
# JA7bTWLqFSLGaTh7ZlbxbsLXA91OOroEpv7OjzFuu3tkpC9FflA4Dp2Euq4+qPmx
# UqfGp+TX0gLRJp9NJOzzILjcTD3rkFFFbxUv1xyg6avivFDLtoKBhM2Td138umE1
# pNOacanuSYtPHIeQHmB6haFi64avLBLwTTAm/Rbit860cFXR72wq+5Qh4hSmezHq
# KXERWPpVBe+APrJ4Iqc+aPeMmIkoCWZQO22HnLNFUFSXjiwyIbgvlH/LIAJEqTaf
# TzxDZgKhlLU7zr6gwsq3WNpcYQI6NuxWnwh3VVDDyF7onQqKs5Ll7bleVN0Y8Vvq
# gE45ppyBbvwqN/Run5fMCCRz3aYMY0kZhKO92eP7t4zHqZ5bQMAgZ0tE2Pz/jb0w
# iykUF/PcoOqqk3vVLiRDYst6vd3GEMNzMpUUvQcvBG46+COIbwIDAQABo4IB3DCC
# AdgwDgYDVR0PAQH/BAQDAgGGMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBSa
# 8VR3dQyHFjdGoKzeefn0f8F46TBUBgNVHSAETTBLMEkGBFUdIAAwQTA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9z
# aXRvcnkuaHRtMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMBIGA1UdEwEB/wQI
# MAYBAf8CAQAwHwYDVR0jBBgwFoAU2UEpsA8PY2zvadf1zSmepEhqMOYwcAYDVR0f
# BGkwZzBloGOgYYZfaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwv
# TWljcm9zb2Z0JTIwSUQlMjBWZXJpZmllZCUyMENvZGUlMjBTaWduaW5nJTIwUENB
# JTIwMjAyMS5jcmwwfQYIKwYBBQUHAQEEcTBvMG0GCCsGAQUFBzAChmFodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIw
# VmVyaWZpZWQlMjBDb2RlJTIwU2lnbmluZyUyMFBDQSUyMDIwMjEuY3J0MA0GCSqG
# SIb3DQEBDAUAA4ICAQCQdVoZ/U0m38l2iKaZFlsxavptpoOLyaR1a9ZK2TSF1kOn
# FJhMDse6KkCgsveoiEjXTVc6Xt86IKHn76Nk5qZB0BXv2iMRQ2giAJmYvZcmstoZ
# qfB2M3Kd5wnJhUJOtF/b6HsqSelY6nhrF06zor1lDmDQixBZcLB9zR1+RKQso1je
# kNxYuUk+HaN3k1S57qk0O//YbkwU0mELCW04N5vICMZx5T5c7Nq/7uLvbVhCdD7f
# 2bZpA4U7vOkB1ooB4AaER3pjoJ0Mad5LFyi6Na9p9Zu/hrLeOjU5FItS5Yxsqvlf
# XxAThJ176CmkYstKRmytSHZ7JhKRfV6e9Zftk/ODb/CK4pGVAVqsOf4337bQGrOH
# HCQ3IvN9gmnUuDh8JdvbheoWPHxIN1GB5sUiY584tXN7xdD8LCSsRqJvQ8e7a3gZ
# WTgViugRs1QWq+N0G9Nje6JHlN1CjJehge+H5PGktJja+juGEr0P+ukSkcL6qaZx
# FQTh3SDI71lvW++3bl/Ezd6SO8N9Udw+reoyvRHCyTiSsplZQSBTVJdPmo3qCpGu
# yHFtPo5CBn3/FPTiqJd3M9BHoqKd0G9Kmg6fGcAvFwnLNXA2kov727wRljL3ypfq
# L7iAT/Ynpxul6RwHRlcOf9dDGg1RRvr92NP/CWVXIb68geR2rvU/NsfmtjF1wDCC
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
# BgNVBAMTIk1pY3Jvc29mdCBJRCBWZXJpZmllZCBDUyBFT0MgQ0EgMDQCEzMABVBv
# 66WDrJVAE3wAAAAFUG8wDQYJYIZIAWUDBAIBBQCgXjAQBgorBgEEAYI3AgEMMQIw
# ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAvBgkqhkiG9w0BCQQxIgQgpOvu
# LDF5by824+d/ftgnzedJowAvlFvfDdGa7s4w+z4wDQYJKoZIhvcNAQEBBQAEggGA
# BUWvGHVuFcj1Msgy9rotftLscDY/GiQZUSL8GGjhKoq6UKNZlEaXpzJH9mYkAtDA
# YyAtGHSELQV2Twqw+/BubNFl1XY/2G1mkMn8oSkMu/JblTNMGmS03LmvXBk95AV8
# ydCAOqzO08aVx2X96hiKzn68A3Ru7AVqWWIpxjk0bWyWabHomQzQE0NGDgXXyPu1
# aS/8kzRo4uoDQZRXeT2q5B4JGvZF4yjft85zKNMoo+CgHq42Aw7r5THt+vCeMiuO
# pyN5+nTs5mBqHFJjVlVXErmkxI+JpBfDlsHeNkuhOhQS5XvZbfeOii6FOR3W/oTN
# h4HLFPD9q8ls9lXLJrOFCJ5wS9uvF7hRxIoNJEMbiDCL5TxabT6EOluNLJ1QOy8D
# pYpmPVTv2Yriitcq7ajlYIS+0YrEPTzZnnGQDE4V9NWeaX1EaQOkuCxeQRZMj9gr
# FYz7kgbA+IEYxWbodeqfcC5h0o5qc9CxRkBmBu/2sF+kIOVhEU9O18x2k2naekBJ
# oYIYFDCCGBAGCisGAQQBgjcDAwExghgAMIIX/AYJKoZIhvcNAQcCoIIX7TCCF+kC
# AQMxDzANBglghkgBZQMEAgEFADCCAWIGCyqGSIb3DQEJEAEEoIIBUQSCAU0wggFJ
# AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIBKnv/QD27hmzNFDDFUc
# uj4opiIqGMzkuSw/YUyfwrPwAgZqhEj7PqwYEzIwMjYwOTAzMTM1MTI4LjAyNFow
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
# CQUxDxcNMjYwOTAzMTM1MTI4WjAvBgkqhkiG9w0BCQQxIgQgRsrIW2S5lGRPkPAo
# 6XglxtBdab0Oc5neIxL0/uHp2+QwgbkGCyqGSIb3DQEJEAIvMYGpMIGmMIGjMIGg
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
# BgkqhkiG9w0BAQsFAAIFAO5D310wIhgPMjAyNjA5MDMxMTU4MjFaGA8yMDI2MDkw
# NDExNTgyMVowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA7kPfXQIBADAKAgEAAgIB
# JgIB/zAHAgEAAgISfzAKAgUA7kUw3QIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgor
# BgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBCwUA
# A4IBAQAwjRmZJIA2Ka+TbqoNKcOLb8MqPVBi+4mcONH8jPvOGrUWunhqfCT43EtG
# wrnTrKpGJClOcL2ybxZRohJ0vGx0fzc5c/kxpY7mv9cLfDdhKoFyQPJGWjCAuwBf
# 6Q1pTGpFH2dwawhpsjORp0OFfSzRHyWFpJvezTuxnth71wFR4t30i0l3g27xyIDk
# 34E3WLJd06O7gi4OugaaFEILwGG4iDFmxrCb7+dK99Dv5+oOnVnjJoDb4PbiEDLT
# hKRjZEX3NLj4jCt8iucE6l51u8p+dy8r+TBLHkw7X6uRSmSBO48PBAu/UBI0jUXZ
# 6PXNUGf6xTMb0lTcppV4Sb6xMlw9MA0GCSqGSIb3DQEBAQUABIICAH440QS4XqpB
# orp0DFEXLFVdj0eQk0WrDKnfm7lI5Vp9hSym02Z4mz75ZnFX4k6MVrg/oC+0gs1g
# JSfI4gCmKaCGglTk7jGzYuYiduio9LJEeLd35I2hwXJHs1TsG+ikZZ3qiBk4r+M4
# z8BMWgkX1pKrNufEL6ZZx+/KQON8ae7QCIUzu3+SvUgrrcwpr3uI57VEwc9WjD+J
# OOaXWLWDlMW3Q5tmv3o65R5cDlj2cDhcdPGjOWxysPimzeKy50BIAE1zeLi8LqId
# tDvX4hQB9XPkeH9WZvfbxowU7h6bkJBXCnSwh+ajtEXwbRmVcpzvPwpspT8mX0+1
# zllDjcSolSTV/5t/oBWFiChpeQPJB4iKiTHqY69VSjy/jVaePbap9fUKRm41MQ8J
# bVCCJti8pSYATZBqgtPKt0c+VjLKkzcmbrG9BancjE6z1alRrDfDjHvj92is8EbV
# bphCpz25i3UuTPUvAr6pdQ12uhckLoZrwAVrcp19AKk/FxJv8HbzjIoelwsYuWtS
# vqyr+DqvCz1HnGWngL3vFRvCSkc5W6O8QdWO9+RPTz+UGCKtdFe5naFjNnIYyX8C
# LawxZdgCaB9x+jW5VxGUNjHsnjtN1uFlYIww7vhgVeYMtm/TFXixQj4qhElakQ8S
# 9u4pTq1IpjDunhfZDvev4tM8oA0Qp9n/
# SIG # End signature block
