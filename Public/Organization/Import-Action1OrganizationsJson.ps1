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

    if ($PSBoundParameters.ContainsKey('MapIndexPath')) {
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
    $mappedSourceIds = @{}

    $mapIndexFile = Test-Path -LiteralPath $mapIndexFilePath -PathType Leaf

    if ($mapIndexFile) {
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
