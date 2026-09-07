# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Import-Action1UsersJson {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingPlainTextForPassword',
        'TemporaryPassword',
        Justification = 'New-Action1User requires a temporary password string for the API body.'
    )]
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            Test-Action1UserPassword -Password $_
        })]
        [string]$TemporaryPassword,

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
        -Schema $Script:Action1_UserJsonSchema `
        -Type 'User'
    $inputValidationMap['organization_id'] = $null

    [void](Test-Action1JsonSchema `
        -Json $inputJson `
        -ValidationMap $inputValidationMap `
        -ObjectType "Source users file: $resolvedInputPath")

    if ($inputJson.items -isnot [System.Array]) {
        Write-Error 'Source users file property ''items'' must be an array.' `
            -ErrorAction Stop
    }

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
        $mapIndexFilePath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($MapIndexPath)
    }
    else {
        $mapIndexFilePath = [System.IO.Path]::ChangeExtension($mapFilePath, '.index.txt')
    }

    $mapIndexParentPath = Split-Path -Path $mapIndexFilePath -Parent

    $filePaths = @(
        $resolvedInputPath, $mapFilePath, $mapIndexFilePath, $inProgressMapFilePath
    )
    $uniqueFilePaths = @{}
    foreach ($filePath in $filePaths) {
        if ($uniqueFilePaths.ContainsKey($filePath)) {
            Write-Error 'Source, map, index, and temporary map paths must be different.' `
                -ErrorAction Stop
        }
        $uniqueFilePaths[$filePath] = $true
    }

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

    if ($PSBoundParameters.ContainsKey('MapIndexPath') -and $mapIndexFile) {
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

    $items = @($inputJson.items)
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
                -Activity 'Import Action1 users from JSON' `
                -Status "Processing $processedCount of $totalCount" `
                -PercentComplete $percentComplete

            $sourceObjectId = Get-FirstPropertyValue `
                -InputObject $item -PropertyName @('id')

            if (-not (Test-Guid -Guid $sourceObjectId)) {
                $failedCount++
                Write-Error 'UserId must be in the standard GUID format.'
                continue
            }

            if ($mappedSourceIds.ContainsKey($sourceObjectId)) {
                $skippedCount++
                Write-Action1Debug (
                    "Skipping source user '$sourceObjectId' because it is mapped."
                )
                continue
            }

            try {
                $newUserParams = @{
                    FirstName   = Get-FirstPropertyValue $item @('first_name')
                    LastName    = Get-FirstPropertyValue $item @('last_name')
                    Email       = Get-FirstPropertyValue $item @('email')
                    Password    = $TemporaryPassword
                    Confirm     = $false
                    ErrorAction = 'Stop'
                }

                foreach ($requiredName in @('FirstName', 'LastName', 'Email')) {
                    if ([string]::IsNullOrWhiteSpace($newUserParams[$requiredName])) {
                        throw "Source user is missing a nonempty $requiredName value."
                    }
                }

                $optionalFields = @{
                    Phone = 'phone'
                    Timezone = 'timezone'
                    Enabled = 'enabled'
                }
                foreach ($parameterName in $optionalFields.Keys) {
                    $value = Get-FirstPropertyValue `
                        -InputObject $item `
                        -PropertyName @($optionalFields[$parameterName])
                    if (-not [string]::IsNullOrWhiteSpace($value)) {
                        $newUserParams[$parameterName] = $value
                    }
                }

                $timeoutValue = Get-FirstPropertyValue $item @('session_timeout')
                if (-not [string]::IsNullOrWhiteSpace($timeoutValue)) {
                    $timeoutSeconds = 0
                    if (
                        -not [int]::TryParse($timeoutValue, [ref]$timeoutSeconds) -or
                        $timeoutSeconds -lt 300 -or $timeoutSeconds -gt 86400 -or
                        $timeoutSeconds % 60 -ne 0
                    ) {
                        $message = 'Source session_timeout must be a whole number '
                        $message += 'of minutes expressed as 300 through 86400 seconds.'
                        throw $message
                    }
                    $newUserParams.SessionTimeout = [int]($timeoutSeconds / 60)
                }
            }
            catch {
                $failedCount++
                Write-Error "Invalid source user '$sourceObjectId'. $($_.Exception.Message)"
                continue
            }

            $targetLabel = "User '$($newUserParams.Email)'"

            if (
                -not $PSCmdlet.ShouldProcess(
                    $targetLabel,
                    "Import source user '$sourceObjectId'"
                )
            ) {
                if (-not $WhatIfPreference) {
                    $skippedCount++
                }

                continue
            }

            $userAlreadyExists = $false
            try {
                if ($Force.IsPresent) {
                    $newUserParams.Force = $true
                }

                # Capture IDs before the POST so recovery cannot select an existing user.
                $existingUserIds = @(
                    foreach ($user in Get-Action1Users -ErrorAction Stop) {
                        $userId = Get-FirstPropertyValue `
                            -InputObject $user -PropertyName @('id')
                        if (-not (Test-Guid -Guid $userId)) {
                            throw 'The pre-create users list contains an invalid user ID.'
                        }
                        $userId
                    }
                )

                try {
                    $createdUser = New-Action1User @newUserParams
                }
                catch {
                    if (Test-Action1UserCreateError `
                        -ErrorRecord $_ `
                        -RequiredText $Script:Action1_UserAlreadyExistsErrorText
                    ) {
                        $createdUser = Resolve-Action1UserByEmail `
                            -Email $newUserParams.Email `
                            -ErrorAction Stop
                        $userAlreadyExists = $true
                        Write-Action1Debug (
                            "User '$($newUserParams.Email)' already exists. " +
                            'Recording its mapping and counting the create as failed.'
                        )
                    }
                    elseif (Test-Action1UserCreateError -ErrorRecord $_) {
                        Write-Action1Debug (
                            "Known HTTP 400 create response for '$($newUserParams.Email)'. " +
                            'Resolving the newly created user from the users list.'
                        )
                        $createdUser = Resolve-Action1CreatedUser `
                            -UserIds $existingUserIds `
                            -Email $newUserParams.Email `
                            -ErrorAction Stop
                    }
                    else {
                        throw
                    }
                }

                if ($null -eq $createdUser) {
                    throw "No created user was returned for '$targetLabel'."
                }
            }
            catch {
                $failedCount++
                $message = "Failed to import source user '$sourceObjectId'. "
                $message += $_.Exception.Message
                Write-Error $message
                continue
            }

            # Stop on persistence errors so the temporary map remains available.
            if (-not $WhatIfPreference) {
                $mapRecordContent = @(',')
                $mapRecordContent += ConvertTo-Action1JsonPropertyContent `
                    -Name $sourceObjectId `
                    -Value $createdUser

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

            if ($userAlreadyExists) {
                $failedCount++
            }
            else {
                $createdCount++
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
        -Activity 'Import Action1 users from JSON' `
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
