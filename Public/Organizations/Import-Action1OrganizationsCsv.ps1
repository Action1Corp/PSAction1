# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Import-Action1OrganizationsCsv {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$MapPath,

        [Parameter(Mandatory = $false)]
        [ValidateSet('CreateNew', 'MatchExisting', 'Skip')]
        [string]$ConflictAction = 'Skip'
    )

    $newMapRow = {
        param(
            [Parameter(Mandatory = $true)]
            [object]$SourceOrganization
        )

        $rowValues = @{
            EntityType         = ([string]$SourceOrganization.EntityType).Trim()
            SourceId           = ([string]$SourceOrganization.Id).Trim()
            SourceName         = ([string]$SourceOrganization.Name).Trim()
            SourceRegion       = ([string]$SourceOrganization.Region).Trim()
            SourceEnterpriseId = ([string]$SourceOrganization.EnterpriseId).Trim()
            TargetRegion       = ''
            TargetEnterpriseId = ''
            TargetId           = ''
            TargetName         = ([string]$SourceOrganization.Name).Trim()
            Status             = ''
            ImportedAt         = ''
        }

        $orderedRow = [ordered]@{}

        foreach ($column in $Script:Action1_OrganizationMigrationMapCsvColumns) {
            $orderedRow[$column] = $rowValues[$column]
        }

        [pscustomobject]$orderedRow
    }

    $newResultObject = {
        param(
            [Parameter(Mandatory = $true)]
            [object]$MapRow,

            [Parameter(Mandatory = $true)]
            [string]$Message
        )

        $orderedResult = [ordered]@{}

        foreach ($column in $Script:Action1_OrganizationMigrationMapCsvColumns) {
            $orderedResult[$column] = $MapRow.$column
        }

        $orderedResult.Message = $Message

        [pscustomobject]$orderedResult
    }

    $saveMapFile = {
        $rowsToWrite = @(
            $mapRows |
                Select-Object -Property $Script:Action1_OrganizationMigrationMapCsvColumns
        )

        if ($rowsToWrite.Count -eq 0) {
            $header = $Script:Action1_OrganizationMigrationMapCsvColumns -join ','
            Set-Content -LiteralPath $resolvedMapPath -Value $header -Encoding UTF8 -ErrorAction Stop
            return
        }

        $csvLines = @($rowsToWrite | ConvertTo-Csv -NoTypeInformation)
        Set-Content -LiteralPath $resolvedMapPath -Value $csvLines -Encoding UTF8 -ErrorAction Stop
    }

    $resolvedSourcePath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path)

    if (-not (Test-Path -LiteralPath $resolvedSourcePath -PathType Leaf)) {
        Write-Error "Source CSV file '$resolvedSourcePath' was not found." -ErrorAction Stop
    }

    if (-not $PSBoundParameters.ContainsKey('MapPath')) {
        $timestamp = Get-UtcTimestamp -Template 'yyMMdd_HHmm'
        $fileName = 'Action1_Organizations_map_{0}.csv' -f $timestamp
        $MapPath = Join-Path -Path (Get-Location) -ChildPath $fileName
    }

    $resolvedMapPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($MapPath)
    $mapParentPath = Split-Path -Path $resolvedMapPath -Parent

    if (-not [string]::IsNullOrWhiteSpace($mapParentPath) -and -not (Test-Path -LiteralPath $mapParentPath)) {
        Write-Action1Debug "Creating map directory '$mapParentPath'."
        $null = New-Item -Path $mapParentPath -ItemType Directory -Force
    }

    Write-Action1Debug "Starting organizations CSV import from '$resolvedSourcePath'."
    Write-Action1Debug "Using organizations migration map '$resolvedMapPath'."
    Write-Action1Debug "Name conflict action is '$ConflictAction'."

    [void](Test-CsvHeader `
        -CsvPath $resolvedSourcePath `
        -RequiredColumns $Script:Action1_OrganizationExportCsvColumns `
        -FileLabel 'Source')

    $sourceOrganizations = @(
        Import-Csv -LiteralPath $resolvedSourcePath -ErrorAction Stop |
            Where-Object { $null -ne $_ }
    )

    if ($sourceOrganizations.Count -eq 0) {
        Write-Error "Source CSV file '$resolvedSourcePath' does not contain organization rows." -ErrorAction Stop
    }

    $sourceIds = @{}
    $sourceRowNumber = 1

    foreach ($sourceOrganization in $sourceOrganizations) {
        $sourceRowNumber++
        $sourceId = ([string]$sourceOrganization.Id).Trim()
        $sourceName = ([string]$sourceOrganization.Name).Trim()
        $entityType = ([string]$sourceOrganization.EntityType).Trim()
        $sourceEnterpriseId = ([string]$sourceOrganization.EnterpriseId).Trim()
        $sourceRegion = ([string]$sourceOrganization.Region).Trim()
        $exportedAt = ([string]$sourceOrganization.ExportedAt).Trim()

        if ([string]::IsNullOrWhiteSpace($sourceId)) {
            Write-Error "Source CSV row $sourceRowNumber has an empty Id value." -ErrorAction Stop
        }

        if (-not (Test-Guid $sourceId)) {
            Write-Error "Source CSV row $sourceRowNumber has an invalid Id value '$sourceId'." -ErrorAction Stop
        }

        if ([string]::IsNullOrWhiteSpace($sourceName)) {
            Write-Error "Source CSV row $sourceRowNumber has an empty Name value." -ErrorAction Stop
        }

        if ([string]::IsNullOrWhiteSpace($entityType)) {
            Write-Error "Source CSV row $sourceRowNumber has an empty EntityType value." -ErrorAction Stop
        }

        if ([string]::IsNullOrWhiteSpace($sourceEnterpriseId)) {
            Write-Error "Source CSV row $sourceRowNumber has an empty EnterpriseId value." -ErrorAction Stop
        }

        if ([string]::IsNullOrWhiteSpace($sourceRegion)) {
            Write-Error "Source CSV row $sourceRowNumber has an empty Region value." -ErrorAction Stop
        }

        if ([string]::IsNullOrWhiteSpace($exportedAt)) {
            Write-Error "Source CSV row $sourceRowNumber has an empty ExportedAt value." -ErrorAction Stop
        }

        if ($sourceIds.ContainsKey($sourceId)) {
            Write-Error "Source CSV file contains duplicate Id value '$sourceId'." -ErrorAction Stop
        }

        $sourceIds[$sourceId] = $true
    }

    $mapRows = New-Object System.Collections.Generic.List[object]
    $mapRowBySourceId = @{}

    if (Test-Path -LiteralPath $resolvedMapPath -PathType Leaf) {
        Write-Action1Debug "Reading existing organizations migration map '$resolvedMapPath'."
        [void](Test-CsvHeader `
            -CsvPath $resolvedMapPath `
            -RequiredColumns $Script:Action1_OrganizationMigrationMapCsvColumns `
            -FileLabel 'Map')

        $existingMapRows = @(
            Import-Csv -LiteralPath $resolvedMapPath -ErrorAction Stop |
                Where-Object { $null -ne $_ }
        )

        foreach ($existingMapRow in $existingMapRows) {
            $sourceId = ([string]$existingMapRow.SourceId).Trim()
            $targetId = ([string]$existingMapRow.TargetId).Trim()
            $status = ([string]$existingMapRow.Status).Trim()

            if ([string]::IsNullOrWhiteSpace($sourceId)) {
                Write-Error "Map CSV file '$resolvedMapPath' contains an empty SourceId value." -ErrorAction Stop
            }

            if (-not (Test-Guid $sourceId)) {
                Write-Error "Map CSV file '$resolvedMapPath' contains invalid SourceId '$sourceId'." -ErrorAction Stop
            }

            if (-not [string]::IsNullOrWhiteSpace($targetId) -and -not (Test-Guid $targetId)) {
                Write-Error "Map CSV file '$resolvedMapPath' contains invalid TargetId '$targetId'." -ErrorAction Stop
            }

            if ($mapRowBySourceId.ContainsKey($sourceId)) {
                $message = (
                    "Map CSV file '$resolvedMapPath' contains duplicate " +
                    "SourceId '$sourceId'."
                )
                Write-Error $message -ErrorAction Stop
            }

            if (
                [string]::IsNullOrWhiteSpace($targetId) -and
                @('Skipped', 'Failed') -notcontains $status
            ) {
                $message = (
                    "Map row for SourceId '$sourceId' has empty TargetId " +
                    "and unsupported Status '$status'."
                )
                Write-Error $message -ErrorAction Stop
            }

            $mapRowValues = @{
                EntityType         = $existingMapRow.EntityType
                SourceId           = $sourceId
                SourceName         = $existingMapRow.SourceName
                SourceRegion       = $existingMapRow.SourceRegion
                SourceEnterpriseId = $existingMapRow.SourceEnterpriseId
                TargetRegion       = $existingMapRow.TargetRegion
                TargetEnterpriseId = $existingMapRow.TargetEnterpriseId
                TargetId           = $targetId
                TargetName         = $existingMapRow.TargetName
                Status             = $status
                ImportedAt         = $existingMapRow.ImportedAt
            }

            $orderedMapRow = [ordered]@{}

            foreach ($column in $Script:Action1_OrganizationMigrationMapCsvColumns) {
                $orderedMapRow[$column] = $mapRowValues[$column]
            }

            $mapRow = [pscustomobject]$orderedMapRow

            [void]$mapRows.Add($mapRow)
            $mapRowBySourceId[$sourceId] = $mapRow
        }
    }

    $targetRegion = Get-Action1Region

    Write-Action1Debug 'Getting target Action1 organizations.'
    $targetOrganizations = @(
        Get-Action1Organizations -ErrorAction Stop |
            Where-Object { $null -ne $_ }
    )
    Write-Action1Debug "Retrieved $($targetOrganizations.Count) target organization record(s)."

    $targetEnterpriseIdFallback = ''

    foreach ($targetOrganization in $targetOrganizations) {
        $enterpriseId = Get-FirstPropertyValue `
            -InputObject $targetOrganization `
            -PropertyName @('EnterpriseId', 'enterprise_id')

        if (-not [string]::IsNullOrWhiteSpace($enterpriseId)) {
            $targetEnterpriseIdFallback = $enterpriseId
            break
        }
    }

    $targetOrganizationsByName = @{}

    foreach ($targetOrganization in $targetOrganizations) {
        $targetName = Get-FirstPropertyValue `
            -InputObject $targetOrganization `
            -PropertyName @('Org_Name', 'name', 'Name')

        if ([string]::IsNullOrWhiteSpace($targetName)) {
            continue
        }

        if (-not $targetOrganizationsByName.ContainsKey($targetName)) {
            $targetOrganizationsByName[$targetName] = New-Object System.Collections.ArrayList
        }

        [void]$targetOrganizationsByName[$targetName].Add($targetOrganization)
    }

    $totalOrganizations = $sourceOrganizations.Count
    $processedOrganizations = 0
    $createdOrganizations = 0
    $matchedOrganizations = 0
    $skippedOrganizations = 0
    $failedOrganizations = 0

    try {
        foreach ($sourceOrganization in $sourceOrganizations) {
            $processedOrganizations++

            $sourceId = ([string]$sourceOrganization.Id).Trim()
            $sourceName = ([string]$sourceOrganization.Name).Trim()
            $description = [string]$sourceOrganization.Description

            $percentComplete = [int](($processedOrganizations / $totalOrganizations) * 100)

            Write-Progress `
                -Activity 'Importing Action1 organizations' `
                -Status ("Processing {0} ({1} of {2})" -f $sourceName, $processedOrganizations, $totalOrganizations) `
                -PercentComplete $percentComplete

            Write-Action1Debug "Processing source organization '$sourceName' with Id '$sourceId'."

            if ($mapRowBySourceId.ContainsKey($sourceId)) {
                $mapRow = $mapRowBySourceId[$sourceId]

                if (-not [string]::IsNullOrWhiteSpace([string]$mapRow.TargetId)) {
                    $skippedOrganizations++
                    Write-Action1Debug (
                        "Skipping source organization '$sourceName' because " +
                        'it already has a TargetId in the map.'
                    )

                    $resultMapRowValues = @{}

                    foreach ($column in $Script:Action1_OrganizationMigrationMapCsvColumns) {
                        $resultMapRowValues[$column] = $mapRow.$column
                    }

                    $resultMapRowValues.Status = 'Skipped'
                    $orderedResultMapRow = [ordered]@{}

                    foreach ($column in $Script:Action1_OrganizationMigrationMapCsvColumns) {
                        $orderedResultMapRow[$column] = $resultMapRowValues[$column]
                    }

                    $resultMapRow = [pscustomobject]$orderedResultMapRow

                    & $newResultObject `
                        -MapRow $resultMapRow `
                        -Message 'Source organization already has a target mapping.'
                    continue
                }

                Write-Action1Debug (
                    "Retrying source organization '$sourceName' from existing " +
                    "map status '$($mapRow.Status)'."
                )
            }
            else {
                $mapRow = & $newMapRow -SourceOrganization $sourceOrganization
                [void]$mapRows.Add($mapRow)
                $mapRowBySourceId[$sourceId] = $mapRow
            }

            $mapRow.EntityType = ([string]$sourceOrganization.EntityType).Trim()
            $mapRow.SourceName = $sourceName
            $mapRow.SourceRegion = ([string]$sourceOrganization.Region).Trim()
            $mapRow.SourceEnterpriseId = ([string]$sourceOrganization.EnterpriseId).Trim()
            $mapRow.TargetRegion = $targetRegion
            $mapRow.TargetEnterpriseId = $targetEnterpriseIdFallback
            $mapRow.TargetName = $sourceName
            $mapRow.ImportedAt = Get-UtcTimestamp

            $targetMatches = @()

            if ($targetOrganizationsByName.ContainsKey($sourceName)) {
                $targetMatches = @($targetOrganizationsByName[$sourceName])
            }

            if ($targetMatches.Count -gt 0) {
                Write-Action1Debug "Found $($targetMatches.Count) target organization match(es) for '$sourceName'."

                if ($ConflictAction -eq 'Skip') {
                    $mapRow.TargetId = ''
                    $mapRow.Status = 'Skipped'
                    $skippedOrganizations++

                    Write-Action1Debug "Skipped source organization '$sourceName' because ConflictAction is Skip."

                    if (-not $WhatIfPreference) {
                        & $saveMapFile
                    }

                    & $newResultObject `
                        -MapRow $mapRow `
                        -Message 'Target organization with the same name exists.'
                    continue
                }

                if ($ConflictAction -eq 'MatchExisting') {
                    if ($targetMatches.Count -gt 1) {
                        $mapRow.TargetId = ''
                        $mapRow.Status = 'Failed'
                        $failedOrganizations++

                        Write-Action1Debug (
                            "Failed matching source organization '$sourceName' " +
                            'because multiple target organizations have the same name.'
                        )

                        if (-not $WhatIfPreference) {
                            & $saveMapFile
                        }

                        & $newResultObject `
                            -MapRow $mapRow `
                            -Message 'Multiple target organizations with the same name exist.'
                        continue
                    }

                    $targetOrganization = $targetMatches[0]
                    $targetId = Get-FirstPropertyValue `
                        -InputObject $targetOrganization `
                        -PropertyName @('Org_ID', 'id', 'Id')
                    $targetEnterpriseId = Get-FirstPropertyValue `
                        -InputObject $targetOrganization `
                        -PropertyName @('EnterpriseId', 'enterprise_id')

                    if ([string]::IsNullOrWhiteSpace($targetEnterpriseId)) {
                        $targetEnterpriseId = $targetEnterpriseIdFallback
                    }

                    $mapRow.TargetId = $targetId
                    $mapRow.TargetEnterpriseId = $targetEnterpriseId
                    $mapRow.Status = 'MatchedExisting'
                    $matchedOrganizations++

                    Write-Action1Debug "Mapped source organization '$sourceName' to existing target Id '$targetId'."

                    if (-not $WhatIfPreference) {
                        & $saveMapFile
                    }

                    & $newResultObject `
                        -MapRow $mapRow `
                        -Message 'Mapped to existing target organization.'
                    continue
                }
            }

            $targetLabel = "Action1 organization '$sourceName'"

            if (-not $PSCmdlet.ShouldProcess($targetLabel, 'Create organization in target enterprise')) {
                $mapRow.TargetId = ''
                $mapRow.Status = 'Skipped'
                $skippedOrganizations++

                Write-Action1Debug "Skipped creating source organization '$sourceName'."

                & $newResultObject `
                    -MapRow $mapRow `
                    -Message 'Organization creation was skipped.'
                continue
            }

            try {
                Write-Action1Debug "Creating target organization '$sourceName'."

                $createdOrganization = New-Action1Organization `
                    -Name $sourceName `
                    -Description $description `
                    -Confirm:$false `
                    -ErrorAction Stop

                if ($null -eq $createdOrganization) {
                    throw "New-Action1Organization returned no organization object."
                }

                $targetId = Get-FirstPropertyValue `
                    -InputObject $createdOrganization `
                    -PropertyName @('Org_ID', 'id', 'Id')
                $targetName = Get-FirstPropertyValue `
                    -InputObject $createdOrganization `
                    -PropertyName @('Org_Name', 'name', 'Name')
                $targetEnterpriseId = Get-FirstPropertyValue `
                    -InputObject $createdOrganization `
                    -PropertyName @('EnterpriseId', 'enterprise_id')

                if ([string]::IsNullOrWhiteSpace($targetId)) {
                    throw 'Created organization response did not contain a target organization ID.'
                }

                if ([string]::IsNullOrWhiteSpace($targetName)) {
                    $targetName = $sourceName
                }

                if ([string]::IsNullOrWhiteSpace($targetEnterpriseId)) {
                    $targetEnterpriseId = $targetEnterpriseIdFallback
                }

                $mapRow.TargetId = $targetId
                $mapRow.TargetName = $sourceName
                $mapRow.TargetEnterpriseId = $targetEnterpriseId
                $mapRow.Status = 'Created'
                $createdOrganizations++

                if (-not $targetOrganizationsByName.ContainsKey($targetName)) {
                    $targetOrganizationsByName[$targetName] = New-Object System.Collections.ArrayList
                }

                [void]$targetOrganizationsByName[$targetName].Add($createdOrganization)

                Write-Action1Debug "Created target organization '$targetName' with Id '$targetId'."

                if (-not $WhatIfPreference) {
                    & $saveMapFile
                }

                & $newResultObject `
                    -MapRow $mapRow `
                    -Message 'Created target organization.'
            }
            catch {
                $mapRow.TargetId = ''
                $mapRow.Status = 'Failed'
                $mapRow.ImportedAt = Get-UtcTimestamp
                $failedOrganizations++

                Write-Action1Debug "Failed importing source organization '$sourceName'. Error: $($_.Exception.Message)"

                if (-not $WhatIfPreference) {
                    & $saveMapFile
                }

                & $newResultObject `
                    -MapRow $mapRow `
                    -Message $_.Exception.Message
            }
        }
    }
    finally {
        Write-Progress -Activity 'Importing Action1 organizations' -Completed
    }

    $summaryMessage = (
        "Organizations import completed. Total:{0}; created:{1}; matched:{2}; skipped:{3}; failed:{4}; map:'{5}'." -f
        $totalOrganizations,
        $createdOrganizations,
        $matchedOrganizations,
        $skippedOrganizations,
        $failedOrganizations,
        $resolvedMapPath
    )

    Write-Action1Debug $summaryMessage
    Write-Information $summaryMessage -InformationAction Continue
}
