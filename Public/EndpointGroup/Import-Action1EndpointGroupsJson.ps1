# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Import-Action1EndpointGroupsJson {
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

    $inputValidationMap = New-Action1JsonHeader `
        -HeaderTemplate ([ordered]@{
            schema          = $null
            datetime        = $null
            region          = $null
            enterprise_id   = $null
            organization_id = $null
            type            = $null
            items           = $null
        }) `
        -PropertyValues ([ordered]@{
            schema          = $Script:Action1_EndpointGroupJsonSchema
            datetime        = $null
            region          = $null
            enterprise_id   = $null
            organization_id = $null
            type            = 'EndpointGroup'
            items           = $null
        })

    [void](Test-Action1JsonSchema `
        -Json $inputJson `
        -ValidationMap $inputValidationMap `
        -ObjectType "Source endpoint groups file: $resolvedInputPath")

    $sourceEnterpriseId = Get-FirstPropertyValue `
        -InputObject $inputJson `
        -PropertyName @('enterprise_id')
    $sourceOrganizationId = Get-FirstPropertyValue `
        -InputObject $inputJson `
        -PropertyName @('organization_id')
    $sourceRegion = Get-FirstPropertyValue `
        -InputObject $inputJson `
        -PropertyName @('region')

    try {
        [void](Test-Guid `
            -Guid $sourceEnterpriseId `
            -Label "Source enterprise ID '$sourceEnterpriseId'")
        [void](Test-Guid `
            -Guid $sourceOrganizationId `
            -Label "Source organization ID '$sourceOrganizationId'")
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
    $targetOrganizationId = Get-Action1DefaultOrgId -ErrorAction Stop

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
                -Activity 'Import Action1 endpoint groups from JSON' `
                -Status "Processing $processedCount of $totalCount" `
                -PercentComplete $percentComplete

            $sourceObjectId = Get-FirstPropertyValue `
                -InputObject $item `
                -PropertyName @('id', 'Id')

            if ([string]::IsNullOrWhiteSpace($sourceObjectId)) {
                $failedCount++
                Write-Error 'Source endpoint group item is missing an id.'
                continue
            }

            $sourceObjectId = $sourceObjectId.Trim()

            if ($mappedSourceIds.ContainsKey($sourceObjectId)) {
                $skippedCount++
                $message = "Skipping source endpoint group '$sourceObjectId' "
                $message += 'because it is mapped.'
                Write-Action1Debug $message
                continue
            }

            $endpointGroupName = Get-FirstPropertyValue `
                -InputObject $item `
                -PropertyName @('name', 'Name')

            $targetLabel = "source endpoint group '$sourceObjectId'"

            if (-not [string]::IsNullOrWhiteSpace($endpointGroupName)) {
                $targetLabel = "endpoint group '$endpointGroupName'"
            }

            if (
                -not $PSCmdlet.ShouldProcess(
                    $targetLabel,
                    "Import source endpoint group '$sourceObjectId'"
                )
            ) {
                if (-not $WhatIfPreference) {
                    $skippedCount++
                }

                continue
            }

            try {
                $endpointGroupDefinitionProperties = @(
                    'name',
                    'description',
                    'include_filter',
                    'include_filter_logic',
                    'exclude_filter',
                    'exclude_filter_logic',
                    'uptime_alerts'
                )

                $endpointGroupDefinitionValues = [ordered]@{}

                foreach ($propertyName in $endpointGroupDefinitionProperties) {
                    $property = $item.PSObject.Properties[$propertyName]

                    if ($null -eq $property) {
                        continue
                    }

                    $endpointGroupDefinitionValues[$propertyName] = $property.Value
                }

                $endpointGroupDefinition = [PSCustomObject](
                    $endpointGroupDefinitionValues
                )

                $newEndpointGroupParams = @{
                    EndpointGroupDefinition = $endpointGroupDefinition
                    Confirm                 = $false
                    ErrorAction             = 'Stop'
                }

                if ($Force.IsPresent) {
                    $newEndpointGroupParams.Force = $true
                }

                $createdEndpointGroup = New-Action1EndpointGroup `
                    @newEndpointGroupParams

                if ($null -eq $createdEndpointGroup) {
                    throw "No created endpoint group was returned for '$targetLabel'."
                }

                if (-not $WhatIfPreference) {
                    $mapRecordContent = @(',')
                    $mapRecordContent += ConvertTo-Action1JsonPropertyContent `
                        -Name $sourceObjectId `
                        -Value $createdEndpointGroup

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
                $message = "Failed to import source endpoint group "
                $message += "'$sourceObjectId'. "
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
        -Activity 'Import Action1 endpoint groups from JSON' `
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
        SourceFile        = $resolvedInputPath
        MapFile           = $mapFilePath
        MapIndexFile      = $mapIndexFilePath
        Processed         = $processedCount
        Skipped           = $skippedCount
        Created           = $createdCount
        Failed            = $failedCount
        SourceRegion      = $sourceRegion
        TargetRegion      = $targetRegion
        EnterpriseId      = $targetEnterpriseId
        OrganizationId    = $targetOrganizationId
    }
}
