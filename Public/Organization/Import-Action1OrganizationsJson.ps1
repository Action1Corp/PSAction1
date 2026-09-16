# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Import-Action1OrganizationsJson {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$MapPath,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$MapIndexPath,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    if ($Force.IsPresent) {
        $ConfirmPreference = 'None'
    }

    # Validate parameter combinations before touching files or tenant context.
    if (
        $PSBoundParameters.ContainsKey('MapIndexPath') -and
        -not $PSBoundParameters.ContainsKey('MapPath')
    ) {
        $message = 'MapPath is required when MapIndexPath is specified.'
        Write-Error $message -ErrorAction Stop
    }

    # Read and validate the source export.
    $resolvedInputPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path)
    $inputJson = Read-JsonFile -Path $Path

    $inputValidationMap = New-Action1JsonSchemaMap `
        -Schema $Script:Action1_OrganizationJsonSchema `
        -Type 'Organization'

    [void](Test-Action1JsonSchema `
        -Json $inputJson `
        -ValidationMap $inputValidationMap `
        -ObjectType "Source organizations file: $resolvedInputPath")

    $sourceEnterpriseId = Get-FirstPropertyValue `
        -InputObject $inputJson `
        -PropertyName @('enterprise_id')
    $sourceRegion = Get-FirstPropertyValue `
        -InputObject $inputJson `
        -PropertyName @('region')

    try {
        [void](Test-Guid `
            -Guid $sourceEnterpriseId `
            -Label "Source enterprise ID '$sourceEnterpriseId'")
    }
    catch {
        Write-Error $_.Exception.Message -ErrorAction Stop
    }

    # Resolve target tenant metadata and migration file paths.
    $targetRegion = Get-Action1Region

    if ([string]::IsNullOrWhiteSpace($targetRegion)) {
        Write-Error 'Current Action1 target region is not configured.' `
            -ErrorAction Stop
    }

    $targetEnterpriseId = Get-Action1EnterpriseId -ErrorAction Stop

    if (-not $PSBoundParameters.ContainsKey('MapPath')) {
        $mapFileName = $Script:Action1_MigrationMappingFileNameTemplate -f `
            $sourceEnterpriseId,
            $targetEnterpriseId
        $MapPath = Join-Path -Path (Get-Location) -ChildPath $mapFileName
    }

    $mapFilePath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($MapPath)
    $inProgressMapFilePath = "$mapFilePath.inprogress"
    $mapParentPath = Split-Path -Path $mapFilePath -Parent
    $mapIndexPathSpecified = $PSBoundParameters.ContainsKey('MapIndexPath')

    if ($mapIndexPathSpecified) {
        $mapIndexFilePath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath(
            $MapIndexPath
        )
    }
    else {
        $mapIndexFilePath = [System.IO.Path]::ChangeExtension(
            $mapFilePath,
            '.index.txt'
        )
    }

    $mapIndexParentPath = Split-Path -Path $mapIndexFilePath -Parent

    if (
        -not [string]::IsNullOrWhiteSpace($mapParentPath) -and
        -not (Test-Path -LiteralPath $mapParentPath)
    ) {
        Write-Action1Debug "Creating migration map directory '$mapParentPath'."

        if (-not $WhatIfPreference) {
            $null = New-Item -Path $mapParentPath -ItemType Directory -Force
        }
    }

    if (
        -not [string]::IsNullOrWhiteSpace($mapIndexParentPath) -and
        -not (Test-Path -LiteralPath $mapIndexParentPath)
    ) {
        Write-Action1Debug (
            "Creating migration map index directory '$mapIndexParentPath'."
        )

        if (-not $WhatIfPreference) {
            $null = New-Item `
                -Path $mapIndexParentPath `
                -ItemType Directory `
                -Force
        }
    }

    # Validate or create the migration map header before any active actions.
    $mappingFile = Test-Path -LiteralPath $mapFilePath -PathType Leaf
    $mappingHeaderValues = New-Action1JsonHeader `
        -HeaderTemplate $Script:Action1_MappingJsonHeader
    $mappingHeaderValues['schema'] = $Script:Action1_MappingJsonSchema
    $mappingHeaderValues['source_region'] = $sourceRegion
    $mappingHeaderValues['source_enterprise_id'] = $sourceEnterpriseId
    $mappingHeaderValues['target_region'] = $targetRegion
    $mappingHeaderValues['target_enterprise_id'] = $targetEnterpriseId

    $mapIndexHeaderValues = New-Action1JsonHeader `
        -HeaderTemplate $Script:Action1_MappingIndexTextHeader
    $mapIndexHeaderValues['schema'] = $Script:Action1_MappingIndexTextSchema
    $mapIndexHeaderValues['source_region'] = $sourceRegion
    $mapIndexHeaderValues['source_enterprise_id'] = $sourceEnterpriseId
    $mapIndexHeaderValues['target_region'] = $targetRegion
    $mapIndexHeaderValues['target_enterprise_id'] = $targetEnterpriseId
    $mapping = $null

    if ($mappingFile) {
        $mapping = Read-JsonFile -Path $mapFilePath
    }
    else {
        $mappingHeaderValues['datetime'] = Get-UtcTimestamp

        $mappingHeader = New-Action1JsonHeader `
            -HeaderTemplate $Script:Action1_MappingJsonHeader `
            -PropertyValues $mappingHeaderValues
        $mapping = [PSCustomObject]$mappingHeader
        $mappingHeaderValues['datetime'] = $null
    }

    $mapValidationMap = New-Action1JsonHeader `
        -HeaderTemplate $Script:Action1_MappingJsonHeader `
        -PropertyValues $mappingHeaderValues

    if ($null -ne $mapping) {
        [void](Test-Action1JsonSchema `
            -Json $mapping `
            -ValidationMap $mapValidationMap `
            -ObjectType "Migration map '$mapFilePath'")
    }

    if (
        -not $WhatIfPreference -and
        (Test-Path -LiteralPath $inProgressMapFilePath -PathType Leaf)
    ) {
        $message = "Temporary migration map file '$inProgressMapFilePath' "
        $message += 'already exists. Review or remove it before importing.'
        Write-Error $message -ErrorAction Stop
    }

    # Build the in-memory source ID map used for skip checks.
    # Derived index files are rebuilt from the authoritative JSON map.
    $mappedSourceIds = @{}

    $mapIndexFile = Test-Path -LiteralPath $mapIndexFilePath -PathType Leaf

    if ($mapIndexPathSpecified -and $mapIndexFile) {
        $mapIndexHeaderError = Get-Action1MappingIndexFileHeaderError `
            -Path $mapIndexFilePath `
            -HeaderValues $mapIndexHeaderValues

        if (-not [string]::IsNullOrWhiteSpace($mapIndexHeaderError)) {
            $message = "Mapping index file '$mapIndexFilePath' header "
            $message += 'does not match the current migration. '
            $message += $mapIndexHeaderError
            Write-Error $message -ErrorAction Stop
        }

        $mapIndexSourceIds = @(
            Read-Action1MappingIndex -Path $mapIndexFilePath
        )

        if (-not $mappingFile -and $mapIndexSourceIds.Count -gt 0) {
            $message = "Mapping index file '$mapIndexFilePath' contains "
            $message += "source IDs, but migration map '$mapFilePath' "
            $message += 'does not exist.'
            Write-Error $message -ErrorAction Stop
        }

        $mappedSourceIds = New-Action1SourceMap `
            -SourceIds $mapIndexSourceIds
    }
    else {
        $mappedSourceIds = New-Action1SourceMap `
            -MapObject $mapping `
            -IgnoredPropertyNames ([string[]]$Script:Action1_MappingJsonHeader.Keys)

        if (-not $WhatIfPreference) {
            New-Action1MappingIndexFile `
                -Path $mapIndexFilePath `
                -HeaderValues $mapIndexHeaderValues `
                -Force

            foreach ($mappedSourceId in @($mappedSourceIds.Keys)) {
                Write-Action1MappingIndexRecord `
                    -Path $mapIndexFilePath `
                    -SourceId $mappedSourceId `
                    -TargetId ([string]$mapping.$mappedSourceId.id) `
                    -Force
            }
        }
    }

    $mapStreamStarted = $false
    $mapStreamClosed = $false
    $importLoopCompleted = $false

    # Prepare the temporary map stream while keeping the last completed map intact.
    if (-not $WhatIfPreference) {
        if ($mappingFile) {
            Copy-Item `
                -LiteralPath $mapFilePath `
                -Destination $inProgressMapFilePath `
                -ErrorAction Stop
            Remove-Action1JsonObjectClosingBrace -Path $inProgressMapFilePath
        }
        else {
            $mapHeaderContent = ConvertTo-Action1JsonObjectContent `
                -InputObject $mapping `
                -OmitClosingBrace
            Write-TextFileContent `
                -Path $inProgressMapFilePath `
                -Content $mapHeaderContent `
                -Force
        }

        $mapStreamStarted = $true
    }

    $items = @(
        $inputJson.items |
            Where-Object { $null -ne $_ }
    )
    $totalCount = $items.Count
    $processedCount = 0
    $skippedCount = 0
    $failedCount = 0
    $createdCount = 0

    # Import source items and append successful mappings to the temporary map.
    try {
        foreach ($item in $items) {
            $processedCount++
            $percentComplete = 100

            if ($totalCount -gt 0) {
                $percentComplete = [int](($processedCount / $totalCount) * 100)
            }

            Write-Progress `
                -Activity 'Import Action1 organizations from JSON' `
                -Status "Processing $processedCount of $totalCount" `
                -PercentComplete $percentComplete

            $identity = Get-Action1OrganizationIdentityFromObject `
                -OrganizationObject $item

            if (-not $identity.IsValid) {
                $failedCount++
                Write-Error $identity.ErrorMessage
                continue
            }

            $sourceObjectId = $identity.Org_ID

            if ($mappedSourceIds.ContainsKey($sourceObjectId)) {
                $skippedCount++
                Write-Action1Debug (
                    "Skipping source organization '$sourceObjectId' because it is mapped."
                )
                continue
            }

            $organizationName = $identity.Org_Name
            $organizationDescription = Get-FirstPropertyValue `
                -InputObject $item `
                -PropertyName @('description', 'Description')

            $targetLabel = New-Action1OrganizationLabel -Org_Name $organizationName

            if ([string]::IsNullOrWhiteSpace($targetLabel)) {
                $targetLabel = "source organization '$sourceObjectId'"
            }

            if (
                -not $PSCmdlet.ShouldProcess(
                    $targetLabel,
                    "Import source organization '$sourceObjectId'"
                )
            ) {
                if (-not $WhatIfPreference) {
                    $skippedCount++
                }

                continue
            }

            try {
                $newOrganizationParams = @{
                    Name        = $organizationName
                    Description = $organizationDescription
                    Confirm     = $false
                    ErrorAction = 'Stop'
                }

                if ($Force.IsPresent) {
                    $newOrganizationParams.Force = $true
                }

                $createdOrganization = New-Action1Organization @newOrganizationParams

                if ($null -eq $createdOrganization) {
                    throw "No created organization was returned for '$targetLabel'."
                }

                if (-not $WhatIfPreference) {
                    $mapRecordContent = @(',')
                    $mapRecordContent += ConvertTo-Action1JsonPropertyContent `
                        -Name $sourceObjectId `
                        -Value $createdOrganization

                    Write-TextFileContent `
                        -Path $inProgressMapFilePath `
                        -Content $mapRecordContent `
                        -Append `
                        -Force
                }

                $mappedSourceIds[$sourceObjectId] = $true

                if (-not $WhatIfPreference) {
                    Write-Action1MappingIndexRecord `
                        -Path $mapIndexFilePath `
                        -SourceId $sourceObjectId `
                        -TargetId ([string]$createdOrganization.id) `
                        -Force
                }

                $createdCount++
            }
            catch {
                $failedCount++
                $message = "Failed to import source organization '$sourceObjectId'. "
                $message += $_.Exception.Message
                Write-Error $message
            }
        }

        $importLoopCompleted = $true
    }
    finally {
        if ($mapStreamStarted -and -not $mapStreamClosed) {
            Write-TextFileContent `
                -Path $inProgressMapFilePath `
                -Content '}' `
                -Append `
                -Force
            $mapStreamClosed = $true
        }
    }

    Write-Progress `
        -Activity 'Import Action1 organizations from JSON' `
        -Completed

    # Validate the completed temporary map and promote it to the final map path.
    if (-not $WhatIfPreference -and $importLoopCompleted) {
        $inProgressMap = Read-JsonFile -Path $inProgressMapFilePath

        [void](Test-Action1JsonSchema `
            -Json $inProgressMap `
            -ValidationMap $mapValidationMap `
            -ObjectType "Migration map '$inProgressMapFilePath'")

        Move-Item `
            -LiteralPath $inProgressMapFilePath `
            -Destination $mapFilePath `
            -Force `
            -ErrorAction Stop
    }

    # Return import statistics.
    [PSCustomObject][ordered]@{
        SourceFile    = $resolvedInputPath
        MapFile       = $mapFilePath
        MapIndexFile  = $mapIndexFilePath
        Processed     = $processedCount
        Skipped       = $skippedCount
        Created       = $createdCount
        Failed        = $failedCount
        SourceRegion  = $sourceRegion
        TargetRegion  = $targetRegion
        EnterpriseId  = $targetEnterpriseId
    }
}

# SIG # Begin signature block
# MII9MQYJKoZIhvcNAQcCoII9IjCCPR4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBCnLWREuiFq+Z8
# L1h5vqaU2V1+qc+l4ct+VNgvevlUmKCCIfYwggXMMIIDtKADAgECAhBUmNLR1FsZ
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
# 03u4aUoqlmZpxJTG9F9urJh4iIAGXKKy7aIwggaoMIIEkKADAgECAhMzAAYrsCUD
# ok6FalIzAAAABiuwMA0GCSqGSIb3DQEBDAUAMFoxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDUyBFT0MgQ0EgMDMwHhcNMjYwOTE0MTk1MjM0WhcNMjYwOTE3
# MTk1MjM0WjBrMQswCQYDVQQGEwJVUzEOMAwGA1UECBMFVGV4YXMxEDAOBgNVBAcT
# B0hvdXN0b24xHDAaBgNVBAoTE0FjdGlvbjEgQ29ycG9yYXRpb24xHDAaBgNVBAMT
# E0FjdGlvbjEgQ29ycG9yYXRpb24wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQCVI8Jq/ow2Mfvld+sBPNm1XkkSASORmRsgRMM7VdVAZX7sBWeUfg7dWBw3
# Adg08um3LEl0n/KZB7o2c8FkhkKqfP0ZpamKBjESpumgA9NIlyC7YLfhYUsFjDEQ
# W8cdXzkOXaT+353m8dcHUDOm80jxl5ElAlOeGW8LkJq5VTrCeRzZDGhZZ3ZSfphG
# t1/eUxcDtOQc5klOlmJ2EkyPKNY9TlhyMRXdAqUKL/KCvQz+QOZiN3h7vus4W0JZ
# afpepyBzdS5BElXJP3PVA7Xs4NMcAYYbFeenMZLfSRlxcvZgGhWtSRDmbiq4di9+
# EkdCIR2FwTh+pxq4ibU46FquLPOk7qiCSmJV5kK2+kYyBac4WyrhIPQjoAv6KtNL
# Ryim2hUqUiwpB16lvLSP0OPlGyNsDdxlqRNJRiWmsBDjvmkPO4qdttKsly1vyWbH
# Bp4XIJOtsklhLfXrh0V9HD05AUay/s5bq+cqfXYfuARsgGC9y7WSc+wwyv/Qd7th
# l6TLrP0CAwEAAaOCAdQwggHQMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeA
# MDsGA1UdJQQ0MDIGCisGAQQBgjdhAQAGCCsGAQUFBwMDBhorBgEEAYI3YYTGyjWC
# 84fIeoPTzfIboMPaLTAdBgNVHQ4EFgQUP4pA7Ia3qR7nLmGl0RN4bApDmlkwHwYD
# VR0jBBgwFoAUa16lNMMFxWJKIVqOq3NgYtSsY4UwZwYDVR0fBGAwXjBcoFqgWIZW
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# SUQlMjBWZXJpZmllZCUyMENTJTIwRU9DJTIwQ0ElMjAwMy5jcmwwdAYIKwYBBQUH
# AQEEaDBmMGQGCCsGAQUFBzAChlhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUyMEVPQyUy
# MENBJTIwMDMuY3J0MFQGA1UdIARNMEswSQYEVR0gADBBMD8GCCsGAQUFBwIBFjNo
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5o
# dG0wDQYJKoZIhvcNAQEMBQADggIBAJXkO183cDuRZfQ+fpONLNL3IAu/iRi5ltCP
# lNY6I/jh5z4M7LCgRMwgbH0ivvvzeZXFnO4d21QQITTMtlRj+ywsdwKHIdx9/aCh
# 05CM/vKZWnyvFj+uZWFJNT5mcgemiGGGtyk6p1vOwPHfUg9jTVvGvjC+97QVCD2w
# lz7/qqE41GExV+PSxkCURxvyojpMyf+aLF5FvEUFzS/R0Ogdg0VHLOK2W4BAvVgw
# LAK+gH47JI0clEh/msUfK7QLY7nkOKOhjYctCZKnWe0CSBl/15h3JP8Jr46gAvQr
# DixOC9II2ndbKRZig/H0hJSOr6loKpzJkyVE3gM74/Mf6LY2CHve0YZPQPqaaCAf
# Xi5ufF1dYAU7NYC2pu8vg8qFHhmDPi0QkaVsvbU9K+DH+m4Jhlu1Dfpk+wjO9H6K
# 34vC5F7+LTuc17IcrQ8bAoswm6uhLh6YtZzEy9klCyvOl/7ZIa6n85q18kVWz5ZN
# tGwzwK260QB5IWWqsDGPOFprAIslHQxibYYGMUKLuJ80WoPCG71VcWi6ymzi4gss
# PkzjhmpjRDz8liAqkwDQq8w4kC0FsX2C0hprO9d1pb6w81MNVoVJBIbfUqA62G3w
# Pub5+FuJhzjuz+F712EhwQoznmIod+T+DgcWJCx4m6sgvaJcCGb0nEWjeLB5PQ4u
# 2+vhKypjMIIGqDCCBJCgAwIBAgITMwAGK7AlA6JOhWpSMwAAAAYrsDANBgkqhkiG
# 9w0BAQwFADBaMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgSUQgVmVyaWZpZWQgQ1MgRU9DIENB
# IDAzMB4XDTI2MDkxNDE5NTIzNFoXDTI2MDkxNzE5NTIzNFowazELMAkGA1UEBhMC
# VVMxDjAMBgNVBAgTBVRleGFzMRAwDgYDVQQHEwdIb3VzdG9uMRwwGgYDVQQKExNB
# Y3Rpb24xIENvcnBvcmF0aW9uMRwwGgYDVQQDExNBY3Rpb24xIENvcnBvcmF0aW9u
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAlSPCav6MNjH75XfrATzZ
# tV5JEgEjkZkbIETDO1XVQGV+7AVnlH4O3VgcNwHYNPLptyxJdJ/ymQe6NnPBZIZC
# qnz9GaWpigYxEqbpoAPTSJcgu2C34WFLBYwxEFvHHV85Dl2k/t+d5vHXB1AzpvNI
# 8ZeRJQJTnhlvC5CauVU6wnkc2QxoWWd2Un6YRrdf3lMXA7TkHOZJTpZidhJMjyjW
# PU5YcjEV3QKlCi/ygr0M/kDmYjd4e77rOFtCWWn6Xqcgc3UuQRJVyT9z1QO17ODT
# HAGGGxXnpzGS30kZcXL2YBoVrUkQ5m4quHYvfhJHQiEdhcE4fqcauIm1OOharizz
# pO6ogkpiVeZCtvpGMgWnOFsq4SD0I6AL+irTS0coptoVKlIsKQdepby0j9Dj5Rsj
# bA3cZakTSUYlprAQ475pDzuKnbbSrJctb8lmxwaeFyCTrbJJYS3164dFfRw9OQFG
# sv7OW6vnKn12H7gEbIBgvcu1knPsMMr/0He7YZeky6z9AgMBAAGjggHUMIIB0DAM
# BgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDA7BgNVHSUENDAyBgorBgEEAYI3
# YQEABggrBgEFBQcDAwYaKwYBBAGCN2GExso1gvOHyHqD083yG6DD2i0wHQYDVR0O
# BBYEFD+KQOyGt6ke5y5hpdETeGwKQ5pZMB8GA1UdIwQYMBaAFGtepTTDBcViSiFa
# jqtzYGLUrGOFMGcGA1UdHwRgMF4wXKBaoFiGVmh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUy
# MEVPQyUyMENBJTIwMDMuY3JsMHQGCCsGAQUFBwEBBGgwZjBkBggrBgEFBQcwAoZY
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQl
# MjBJRCUyMFZlcmlmaWVkJTIwQ1MlMjBFT0MlMjBDQSUyMDAzLmNydDBUBgNVHSAE
# TTBLMEkGBFUdIAAwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMA0GCSqGSIb3DQEBDAUAA4IC
# AQCV5DtfN3A7kWX0Pn6TjSzS9yALv4kYuZbQj5TWOiP44ec+DOywoETMIGx9Ir77
# 83mVxZzuHdtUECE0zLZUY/ssLHcChyHcff2godOQjP7ymVp8rxY/rmVhSTU+ZnIH
# pohhhrcpOqdbzsDx31IPY01bxr4wvve0FQg9sJc+/6qhONRhMVfj0sZAlEcb8qI6
# TMn/mixeRbxFBc0v0dDoHYNFRyzitluAQL1YMCwCvoB+OySNHJRIf5rFHyu0C2O5
# 5DijoY2HLQmSp1ntAkgZf9eYdyT/Ca+OoAL0Kw4sTgvSCNp3WykWYoPx9ISUjq+p
# aCqcyZMlRN4DO+PzH+i2Ngh73tGGT0D6mmggH14ubnxdXWAFOzWAtqbvL4PKhR4Z
# gz4tEJGlbL21PSvgx/puCYZbtQ36ZPsIzvR+it+LwuRe/i07nNeyHK0PGwKLMJur
# oS4emLWcxMvZJQsrzpf+2SGup/OatfJFVs+WTbRsM8CtutEAeSFlqrAxjzhaawCL
# JR0MYm2GBjFCi7ifNFqDwhu9VXFousps4uILLD5M44ZqY0Q8/JYgKpMA0KvMOJAt
# BbF9gtIaazvXdaW+sPNTDVaFSQSG31KgOtht8D7m+fhbiYc47s/he9dhIcEKM55i
# KHfk/g4HFiQseJurIL2iXAhm9JxFo3iweT0OLtvr4SsqYzCCBygwggUQoAMCAQIC
# EzMAAAAVBT5uGY6TKdkAAAAAABUwDQYJKoZIhvcNAQEMBQAwYzELMAkGA1UEBhMC
# VVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE0MDIGA1UEAxMrTWlj
# cm9zb2Z0IElEIFZlcmlmaWVkIENvZGUgU2lnbmluZyBQQ0EgMjAyMTAeFw0yNjAz
# MjYxODExMjhaFw0zMTAzMjYxODExMjhaMFoxCzAJBgNVBAYTAlVTMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJRCBW
# ZXJpZmllZCBDUyBFT0MgQ0EgMDMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQDg9Ms9AqovDnMePvMOe+KybhCd8+lokzYORlS3kBVXseecbyGwBcsenlm5
# bLtMGPjiIFLzBQF+ghlVV/U29q5GcdeEEBCHTTGhL2koIrLc4UrliMRcbv9mOMtR
# /l7/xAmv0Fx4BJHn1dHt37fvrBqXmKjKfGf5DpyO/+hnV7TEreMtS19iO+bjZ/9H
# npg3PCk0e7YSbRTFkx97FZwRWpC4s3NepRfRXQh/WMAj7JmsYeVZohi4TF5yW2JM
# rJZqwHcyzJZYtD2Hlno5ZEJkdiZcEaxHOobmwO06Z1J9c23ps9PGIhGaq1sKLEAz
# 9Doc5rLkYWGteDrscKhAp2kIc/oYlH9Ij6BkOqqgWINEkEtC8ZNG1Mak+h3o65aj
# 0iQKmdxW7IZaHO5cuyoMi+KtYfXeIIg3sVIbS2EL8kUtsDGdEqNqAq/isqTi1jXq
# Le6iKp1ni1SPdvPW9G03CTsYF68b/yuIQRwbdoBCXemMNJCS0dorCRY4b2WAAy4n
# g7SANcEgrBgZf535+QfLU5hGzrKjIpbMabauWb5FKWUKkMsPcXFkXRWO4noKPm4K
# WlFypqOpbJ/KONVReIlxHQRegAOBzIhRB7gr9IDQ1sc2MgOgQ+xVGW4oq4HD0mfA
# iwiyLskZrkaQ7JoanYjBNcR9RS26YxAVbcBtLitFTzCIEg5ZdQIDAQABo4IB3DCC
# AdgwDgYDVR0PAQH/BAQDAgGGMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRr
# XqU0wwXFYkohWo6rc2Bi1KxjhTBUBgNVHSAETTBLMEkGBFUdIAAwQTA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9z
# aXRvcnkuaHRtMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMBIGA1UdEwEB/wQI
# MAYBAf8CAQAwHwYDVR0jBBgwFoAU2UEpsA8PY2zvadf1zSmepEhqMOYwcAYDVR0f
# BGkwZzBloGOgYYZfaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwv
# TWljcm9zb2Z0JTIwSUQlMjBWZXJpZmllZCUyMENvZGUlMjBTaWduaW5nJTIwUENB
# JTIwMjAyMS5jcmwwfQYIKwYBBQUHAQEEcTBvMG0GCCsGAQUFBzAChmFodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIw
# VmVyaWZpZWQlMjBDb2RlJTIwU2lnbmluZyUyMFBDQSUyMDIwMjEuY3J0MA0GCSqG
# SIb3DQEBDAUAA4ICAQBdbiI8zwXLX8glJEh/8Q22UMCUhWBO46Z9FPhwOR3mdlqR
# VLkYOon/MczUwrjDhx3X99SPH5PSflkGoTvnO9ZWHM5YFVYpO7NYuB+mfVSGAGZw
# iGOASWk0i2B7vn9nElJJmoiXxugfH5YdBsrUgTt0AFNXkzmqTgk+S1Hxb1u/0HCq
# EHVZPk2A/6eJXYbtpRM5Fcz00jisUl9BRZgSebODV85bBzOveqyC3f0PnHCxRJNh
# Mb8xP/sB/VI7pf2rheSV7zqUSv8vn/fIMblXeaVIlpqoq8SP9BJMjE/CoVXJxnkZ
# QRM1Fa7kN9yztvReOhxSgPgpZx/Xl/jkwyEFVJTBfBp3sTgfIc/pmqv2ehtakL2A
# Ej78EmOPQohxJT3wyX+P78GA25tLpAvzj3RMMHd8z18ZuuVi+60MAzGpOASH1L8N
# lr3fZRZnQO+pyye2DCvYmHaIfdUgYJqn7noxxGVv89+RaETh1tgCDvwNpFCSG7vl
# 5A4ako+2fx409r9TWjXC7Oif1IQ5ZJzB4Rf8GvBiHYjvMmHpledp1FGRLdSRFVpC
# 3/OKpZY6avIqZp7+8pP/WQP903DdgrvAT6W4xPOBxXPa4tGksN3SuqJaiFYHSNye
# Bufn8iseujW4IbBSbHD4BPqbF3qZ+7nG9d/d/G2/Lx4kH9cCmBfmsZdSkHmukDCC
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
# aC1ZOmBXiCRKJLj4DT2uhJ04ji+tHD6n58vhavFIrmcxghqRMIIajQIBATBxMFox
# CzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzAp
# BgNVBAMTIk1pY3Jvc29mdCBJRCBWZXJpZmllZCBDUyBFT0MgQ0EgMDMCEzMABiuw
# JQOiToVqUjMAAAAGK7AwDQYJYIZIAWUDBAIBBQCgXjAQBgorBgEEAYI3AgEMMQIw
# ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAvBgkqhkiG9w0BCQQxIgQgtzNm
# Ot7kxq38jZZnLsEo+84k3uYkDuQesz5TzSAledwwDQYJKoZIhvcNAQEBBQAEggGA
# ZSONAQD6pj4HI2DE6xosR8iE/vhiLJJtU/6g87ByfARk7KicmysGRuO003Npe/17
# zeXzSyrLMxQGNIZg7Lpn6LhBInylV0OH+Eamde7b3+v7hJ3bPrlJh5ZGjS2Il1sd
# 5aFu62Gusuru01Pkej5xfnX1yYniW4c7k/NKnE1KE8+sZDvLtZ3kXVo1cqgKcYKj
# 7TfzTdPSeuNe5aVnkXY2UxLoWgdINzCXXqoxYBVCYeIZlCtcSATJj6sircHqcvBm
# ZPicm3gTw13jWpmBwZ2txEGgzb5LkhSK2GKnw8hK+okRGx0mbzffYhSJZRBgkT8i
# FwvDShFLSyND/6FfoNpchWMKNpnFmy9Me2Aw3rPohSrjTMZisoSHp2IKBe6RZUR6
# 3tjRzuaAMxCnHpoJd6yecPxUS1cabo0wMEJdKmQfBfIBS6Jbaig4/foBLsRYplz1
# ApV9qVup6frcqTKk1ZjGIylJceC2jySVCGT95SclArUOsQab2hNGAD7eCtBJ89Ms
# oYIYETCCGA0GCisGAQQBgjcDAwExghf9MIIX+QYJKoZIhvcNAQcCoIIX6jCCF+YC
# AQMxDzANBglghkgBZQMEAgEFADCCAWIGCyqGSIb3DQEJEAEEoIIBUQSCAU0wggFJ
# AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIOabuKhGZo6gUTyTNH5F
# T9UGUlP79p5WMPnb0/cQJpyPAgZqqYKqHHQYEzIwMjYwOTE2MTAzODM1LjA2OVow
# BIACAfSggeGkgd4wgdsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNV
# BAsTHm5TaGllbGQgVFNTIEVTTjo3ODAwLTA1RTAtRDk0NzE1MDMGA1UEAxMsTWlj
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
# AF1bMIIHlzCCBX+gAwIBAgITMwAAAFck05XgounJMQAAAAAAVzANBgkqhkiG9w0B
# AQwFADBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcg
# Q0EgMjAyMDAeFw0yNTEwMjMyMDQ2NTNaFw0yNjEwMjIyMDQ2NTNaMIHbMQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3Nv
# ZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046
# NzgwMC0wNUUwLUQ5NDcxNTAzBgNVBAMTLE1pY3Jvc29mdCBQdWJsaWMgUlNBIFRp
# bWUgU3RhbXBpbmcgQXV0aG9yaXR5MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAsWylCpMIfbizJLY1kPXO2cmX2HRWvRbAmeKSZ5ex7/jCymdV7Eap+Ic2
# iqRtWDkKKe5gL6JV80wtn5C2qHJLPxUYFKNG3UkHkAI21MoCN+YWnhT8K/YuPib6
# +6970jdbeFKIiZMWwd5hnpX9J3jeteuEdXbp/DfFBK15JuD3JOzWuF2suQCPgqYj
# QPk/gpq+3KCKtXJRbXSCSJ9YtITU2IHwmfdE7l2PfZ154w041po+fDeTj0gJOzcV
# /Jv56Q0M+w19jAKo/I5PEzrLV1IPQnmP4or1X4RbJXk8ONXyOOfXOxK2VLpNxgkl
# K1yAezbFP2uzqihaXkW1h9GQLGENKESnezwgdRaLNNaYtm8AT/pZHYJ35mZVqkZd
# MIckpQHJk/F1fSLyDKeKtH4TC4cc3ESKUMgItq07ZZm74JCsfhmrQ1ijVNDi1Sln
# +QBamgC7WviZbkQnceQRq9DY+6hANwOrasAZUiVr2kPuj1jHDOXzUG4O9QTK70P/
# oXSqZAN1oTv3UfF8JTGmAxg+l1ZPOz50MY96HBDw/3bI/wBGNvLk6fLVnrxGN5B5
# unF/lYvjjWbIUdyBPVQnPOKXu08SRHbY19M1HoWX6PNZv+vzSeqVeWWHKdKjC3Gj
# VjbbGpi+JLbiyaKRSwEqo49tJLvu69cQ7dWsbksai4TURnVj2mMCAwEAAaOCAcsw
# ggHHMB0GA1UdDgQWBBSOg8leLTUOAglIZ+bjXpiD7RKSpzAfBgNVHSMEGDAWgBRr
# aSg6NS9IY0DPe9ivSek+2T3bITBsBgNVHR8EZTBjMGGgX6BdhltodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBQdWJsaWMlMjBS
# U0ElMjBUaW1lc3RhbXBpbmclMjBDQSUyMDIwMjAuY3JsMHkGCCsGAQUFBwEBBG0w
# azBpBggrBgEFBQcwAoZdaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# ZXJ0cy9NaWNyb3NvZnQlMjBQdWJsaWMlMjBSU0ElMjBUaW1lc3RhbXBpbmclMjBD
# QSUyMDIwMjAuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUH
# AwgwDgYDVR0PAQH/BAQDAgeAMGYGA1UdIARfMF0wUQYMKwYBBAGCN0yDfQEBMEEw
# PwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9j
# cy9SZXBvc2l0b3J5Lmh0bTAIBgZngQwBBAIwDQYJKoZIhvcNAQEMBQADggIBAHJ1
# wHY86Zk5SUBDPY25d/u9YJVaaNa71uxjX4cyO/XJ4uPENCSOwkRTnNogPLxTD0Fg
# 3z4TFf/2T/0IFSxdtWVtTjhzrn+WLInzeRawUhTCFVrPBJKEWVshm+Ig7/nB7JbJ
# N88+ltImBbL5kT1StBLfG6UksAcDbNSQww90CUXhGueBxlnSvjkAX1ohiN16y1bB
# 2s0rvQx8Csepl2CuBefTfDrMGzW/tzNx5YaK2D8OWweqTWZcGlJO4YjZNI83cTrQ
# ghfHl/8AXOHj8cWL3wEFltQQs2xeRYAb3Kdnl7oIWKKXWaBYJY5P3QPsiC+DTMp7
# ejdYKTrb396f3gr+wL/Ms5/Z3vIWZPJJv18qNw40fUNveRnwzMQnx8dM2bGuXXQZ
# 5y7P8aXT4HJMo349qZtn4XQwiUE/DDp++MUL0kgjvd/Deo7Xr371PFPPYb4TboZh
# jV1x9+wCHDoOpNCBt+VuXU78ytJdKzQ1Jv2cEP1F9H9/wSLsMDUvWME7u9mGElOP
# DZPMVr8AuBEuLdbTSEdaLwsZBplzxLBcgxhZ/Cs30yBhuE3QhqT1YDZ2pa56RexP
# A2SasPcToT6gJgJ6E06BmZ2zQTNvWOjs5XQqHbYuXcoeDcwe2UaC7EDOGD8GmLE9
# LiqtQsuQCM7v7I2xR+sPZT2Ax/85HjIkM+3MzTK1MYIHQzCCBz8CAQEweDBhMQsw
# CQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYD
# VQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMAIT
# MwAAAFck05XgounJMQAAAAAAVzANBglghkgBZQMEAgEFAKCCBJwwEQYLKoZIhvcN
# AQkQAg8xAgUAMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0B
# CQUxDxcNMjYwOTE2MTAzODM1WjAvBgkqhkiG9w0BCQQxIgQg08H6weoPNxJjwZcV
# n3YaXm8e7BoKtMQnj+7agCLxQBwwgbkGCyqGSIb3DQEJEAIvMYGpMIGmMIGjMIGg
# BCD1PJ9ktQVuTGWIbKLO4f1VUOlUU29ARCEpDZmFTHjbUjB8MGWkYzBhMQswCQYD
# VQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQD
# EylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMAITMwAA
# AFck05XgounJMQAAAAAAVzCCA14GCyqGSIb3DQEJEAISMYIDTTCCA0mhggNFMIID
# QTCCAikCAQEwggEJoYHhpIHeMIHbMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046NzgwMC0wNUUwLUQ5NDcxNTAzBgNV
# BAMTLE1pY3Jvc29mdCBQdWJsaWMgUlNBIFRpbWUgU3RhbXBpbmcgQXV0aG9yaXR5
# oiMKAQEwBwYFKw4DAhoDFQD9LzE5nEJRAUE2Ss3xaKKPXHnLw6BnMGWkYzBhMQsw
# CQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYD
# VQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMDAN
# BgkqhkiG9w0BAQsFAAIFAO5Uqe0wIhgPMjAyNjA5MTYwNTM4NTNaGA8yMDI2MDkx
# NzA1Mzg1M1owdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA7lSp7QIBADAHAgEAAgI1
# 1jAHAgEAAgISKzAKAgUA7lX7bQIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEE
# AYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBCwUAA4IB
# AQBXO+Up7PI+IzDvbY2t9pihUOSgP5mNyc1XsQjcFPSsNo5AVL/zF33S3YT1VFkX
# li8j9RhMy31ddJOg+Qeo0HZAK/LxvX2HnT0klnp0MkNUkzUGbk4xsZy0A/1RJK9t
# Li7QpcinKOTKBNZAfBcHemLDJ1sLiQyEhh5hoEqgG1uBn3gWEm8ZRkOXv3heB0RT
# awNtgcbHp5Zar3CogMLHHzlocB9UXu5xmZsasXUhRbu7oY+CsP1Fss73KjznYT4D
# P5udExg+Hq6Di3GRAmFVd4ASqrOVC0+9E6vxUqn4MhMWQ9TCkM9QKuhKCbePxVNW
# g1ujdEN3TAZKELgFCrqWoHp9MA0GCSqGSIb3DQEBAQUABIICAAl3McyXZKqDxrTO
# Wsp5G9raR0I1gFzsB78kyGkCQI5PIEKmdACUZOfDoiehQvRrDOHhVpTMnc5S3p5m
# d87ctRcPElhNow9lhUlPYwX6996WtLDkVlA21Bvjvh5ffjzWXdxwqOuqZa5qlP7z
# 9tt8c138gRQx0HSEESfqZdpuinYc17Ewj6SMbmZSvGBDPs00Qkf5Kzoodxtg7cq9
# XV5rOCD9CnTSIJoy87hY1Im1OdLWG14FuUDgGq/OQa9Yx0VuD4XIgV/vJGlToYuM
# UQnPsB5XkOnTpiLl7964VrNRMJ0GLOchbPJMNMzKmfOQqzizelk8j7rqmGXb5MV2
# i+IHW0oIwk+qAK7nB3/2ZHAYA2KXC25cNePd/Mh5R2e8YnbwXWN+0KJ9VjmiVs5w
# ymcVWUsnsEAV6igcuVQcd/Qzqz9XyM/sIP1/2nGwEchssRIGWrvyUHvVDOuV3qUV
# wWMxQizKvPw8PkK1LDHgwTT/9IkF/mBubUpIY6Hm87Atn3Z/BFNXetgzwmNAcDNb
# rk72LFJjEHGXnfPixiYabC8UgELTRtTE7lzACCKXj56VrWMYmBevzP5PZSc7Wfgo
# khtCihBDzgs8mCyFEcjZLMTtxnXdPUdUbjgjv/JVIftebZH9sdW4hWwld6xto+sm
# uSXrStxxAhkPv0AUCeIpLDVEyFlP
# SIG # End signature block
