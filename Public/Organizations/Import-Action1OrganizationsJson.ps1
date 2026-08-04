# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

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
        [ValidateSet('Duplicate', 'MergeExisting', 'SkipExisting')]
        [string]$ConflictAction = 'MergeExisting',

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    $newMapItem = {
        param(
            [Parameter(Mandatory = $true)]
            [object]$SourceOrganization
        )

        [PSCustomObject][ordered]@{
            id          = $null
            name        = ([string]$SourceOrganization.name).Trim()
            description = [string]$SourceOrganization.description
            status      = ''
            imported_at = ''
        }
    }

    $newResultObject = {
        param(
            [Parameter(Mandatory = $true)]
            [string]$SourceId,

            [Parameter(Mandatory = $true)]
            [object]$MapItem,

            [Parameter(Mandatory = $true)]
            [string]$Message
        )

        [PSCustomObject][ordered]@{
            source_id   = $SourceId
            id          = $MapItem.id
            name        = $MapItem.name
            description = $MapItem.description
            status      = $MapItem.status
            imported_at = $MapItem.imported_at
            message     = $Message
        }
    }

    $saveMapFile = {
        $orderedItems = [ordered]@{}

        foreach ($sourceId in $mapSourceOrder) {
            if ($mapItemsBySourceId.Contains($sourceId)) {
                $orderedItems[$sourceId] = $mapItemsBySourceId[$sourceId]
            }
        }

        $mapObject = [PSCustomObject][ordered]@{
            schema   = $Script:Action1_OrganizationMigrationMapJsonSchema
            datetime = Get-UtcTimestamp
            type     = 'Organization'
            source   = [PSCustomObject][ordered]@{
                region        = $sourceRegion
                enterprise_id = $sourceEnterpriseId
            }
            target   = [PSCustomObject][ordered]@{
                region        = $targetRegion
                enterprise_id = $targetEnterpriseId
            }
            items    = [PSCustomObject]$orderedItems
        }

        $jsonContent = $mapObject | ConvertTo-Json -Depth 6
        Set-Content -LiteralPath $resolvedMapPath -Value $jsonContent -Encoding UTF8 -ErrorAction Stop
    }

    $confirmImportAction = {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Target,

            [Parameter(Mandatory = $true)]
            [string]$Action
        )

        if ($Force.IsPresent -and -not $WhatIfPreference) {
            return $true
        }

        return $PSCmdlet.ShouldProcess($Target, $Action)
    }

    $resolvedSourcePath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path)

    if (-not (Test-Path -LiteralPath $resolvedSourcePath -PathType Leaf)) {
        Write-Error "Source JSON file '$resolvedSourcePath' was not found." -ErrorAction Stop
    }

    if (-not $PSBoundParameters.ContainsKey('MapPath')) {
        $timestamp = Get-UtcTimestamp -Template 'yyMMdd_HHmm'
        $fileName = 'Action1_Organizations_map_{0}.json' -f $timestamp
        $MapPath = Join-Path -Path (Get-Location) -ChildPath $fileName
    }

    $resolvedMapPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($MapPath)
    $mapParentPath = Split-Path -Path $resolvedMapPath -Parent

    if (
        -not [string]::IsNullOrWhiteSpace($mapParentPath) -and
        -not (Test-Path -LiteralPath $mapParentPath)
    ) {
        Write-Action1Debug "Creating map directory '$mapParentPath'."
        $null = New-Item -Path $mapParentPath -ItemType Directory -Force
    }

    Write-Action1Debug "Starting organizations JSON import from '$resolvedSourcePath'."
    Write-Action1Debug "Using organizations migration map '$resolvedMapPath'."
    Write-Action1Debug "Name conflict action is '$ConflictAction'."

    $sourceJsonContent = Get-Content -LiteralPath $resolvedSourcePath -Raw -ErrorAction Stop

    $sourceJson = ConvertFrom-Json -InputObject $sourceJsonContent -ErrorAction Stop

    $sourceRegion = ([string]$sourceJson.region).Trim()
    $sourceEnterpriseId = ([string]$sourceJson.enterprise_id).Trim()
    $sourceOrganizations = @($sourceJson.items | Where-Object { $null -ne $_ })

    if ($sourceOrganizations.Count -eq 0) {
        Write-Error "Source JSON file '$resolvedSourcePath' does not contain organization items." `
            -ErrorAction Stop
    }

    $mapItemsBySourceId = [ordered]@{}
    $mapSourceOrder = New-Object System.Collections.Generic.List[string]

    if (Test-Path -LiteralPath $resolvedMapPath -PathType Leaf) {
        Write-Action1Debug "Reading existing organizations migration map '$resolvedMapPath'."

        $mapJsonContent = Get-Content -LiteralPath $resolvedMapPath -Raw -ErrorAction Stop

        if ([string]::IsNullOrWhiteSpace($mapJsonContent)) {
            Write-Error "Map JSON file '$resolvedMapPath' is empty." -ErrorAction Stop
        }

        try {
            $mapJson = ConvertFrom-Json -InputObject $mapJsonContent -ErrorAction Stop
        }
        catch {
            Write-Error "Map JSON file '$resolvedMapPath' is not valid JSON. $($_.Exception.Message)" `
                -ErrorAction Stop
        }

        if (-not (Test-ObjectProperties `
            -InputObject $mapJson `
            -PropertyNames @('schema', 'datetime', 'type', 'source', 'target', 'items') `
            -ObjectName 'Map JSON')) {
            Write-Error 'Map JSON is missing one or more required properties.' -ErrorAction Stop
        }

        if ([string]$mapJson.schema -ne $Script:Action1_OrganizationMigrationMapJsonSchema) {
            $message = "Map JSON schema '$($mapJson.schema)' is not supported. "
            $message += "Expected '$Script:Action1_OrganizationMigrationMapJsonSchema'."
            Write-Error $message -ErrorAction Stop
        }

        if ([string]$mapJson.type -ne 'Organization') {
            Write-Error "Map JSON type '$($mapJson.type)' is not supported." -ErrorAction Stop
        }

        if (-not (Test-ObjectProperties `
            -InputObject $mapJson.source `
            -PropertyNames @('region', 'enterprise_id') `
            -ObjectName 'Map JSON source')) {
            Write-Error 'Map JSON source is missing one or more required properties.' `
                -ErrorAction Stop
        }

        if (-not (Test-ObjectProperties `
            -InputObject $mapJson.target `
            -PropertyNames @('region', 'enterprise_id') `
            -ObjectName 'Map JSON target')) {
            Write-Error 'Map JSON target is missing one or more required properties.' `
                -ErrorAction Stop
        }

        foreach ($mapItemProperty in $mapJson.items.PSObject.Properties) {
            $sourceId = ([string]$mapItemProperty.Name).Trim()
            $mapItem = $mapItemProperty.Value

            if ([string]::IsNullOrWhiteSpace($sourceId)) {
                Write-Error "Map JSON file '$resolvedMapPath' contains an empty source id." `
                    -ErrorAction Stop
            }

            if (-not (Test-Guid $sourceId)) {
                Write-Error "Map JSON file '$resolvedMapPath' contains invalid source id '$sourceId'." `
                    -ErrorAction Stop
            }

            $mapItemLabel = "Map JSON item '$sourceId'"

            if (-not (Test-ObjectProperties `
                -InputObject $mapItem `
                -PropertyNames @('id', 'name', 'description', 'status', 'imported_at') `
                -ObjectName $mapItemLabel)) {
                Write-Error "$mapItemLabel is missing one or more required properties." `
                    -ErrorAction Stop
            }

            $targetId = $null

            if ($null -ne $mapItem.id) {
                $targetId = ([string]$mapItem.id).Trim()
            }

            $status = ([string]$mapItem.status).Trim()

            if (-not [string]::IsNullOrWhiteSpace($targetId) -and -not (Test-Guid $targetId)) {
                Write-Error "Map JSON item '$sourceId' contains invalid target id '$targetId'." `
                    -ErrorAction Stop
            }

            if (@('Created', 'Updated', 'Skipped', 'Failed') -notcontains $status) {
                Write-Error "Map JSON item '$sourceId' has unsupported status '$status'." `
                    -ErrorAction Stop
            }

            if (
                [string]::IsNullOrWhiteSpace($targetId) -and
                @('Skipped', 'Failed') -notcontains $status
            ) {
                $message = "Map item for source id '$sourceId' has null id "
                $message += "and unsupported status '$status'."
                Write-Error $message -ErrorAction Stop
            }

            $orderedMapItem = [PSCustomObject][ordered]@{
                id          = if ([string]::IsNullOrWhiteSpace($targetId)) { $null } else { $targetId }
                name        = [string]$mapItem.name
                description = [string]$mapItem.description
                status      = $status
                imported_at = [string]$mapItem.imported_at
            }

            $mapItemsBySourceId[$sourceId] = $orderedMapItem
            [void]$mapSourceOrder.Add($sourceId)
        }
    }

    $targetRegion = Get-Action1Region
    $targetEnterpriseId = Get-Action1EnterpriseId -ErrorAction Stop

    Write-Action1Debug 'Getting target Action1 organizations.'
    $targetOrganizations = @(
        Get-Action1Organizations -ErrorAction Stop |
            Where-Object { $null -ne $_ }
    )
    Write-Action1Debug "Retrieved $($targetOrganizations.Count) target organization record(s)."

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
    $updatedOrganizations = 0
    $skippedOrganizations = 0
    $failedOrganizations = 0

    try {
        foreach ($sourceOrganization in $sourceOrganizations) {
            $processedOrganizations++

            $sourceId = ([string]$sourceOrganization.id).Trim()
            $sourceName = ([string]$sourceOrganization.name).Trim()
            $description = [string]$sourceOrganization.description

            $percentComplete = [int](($processedOrganizations / $totalOrganizations) * 100)

            Write-Progress `
                -Activity 'Importing Action1 organizations' `
                -Status ("Processing {0} ({1} of {2})" -f $sourceName, $processedOrganizations, $totalOrganizations) `
                -PercentComplete $percentComplete

            Write-Action1Debug "Processing source organization '$sourceName' with id '$sourceId'."

            if ($mapItemsBySourceId.Contains($sourceId)) {
                $mapItem = $mapItemsBySourceId[$sourceId]

                if ($null -ne $mapItem.id -and -not [string]::IsNullOrWhiteSpace([string]$mapItem.id)) {
                    $skippedOrganizations++
                    Write-Action1Debug (
                        "Skipping source organization '$sourceName' because " +
                        'it already has a target id in the map.'
                    )

                    $resultMapItem = [PSCustomObject][ordered]@{
                        id          = $mapItem.id
                        name        = $mapItem.name
                        description = $mapItem.description
                        status      = 'Skipped'
                        imported_at = $mapItem.imported_at
                    }

                    & $newResultObject `
                        -SourceId $sourceId `
                        -MapItem $resultMapItem `
                        -Message 'Source organization already has a target mapping.'
                    continue
                }

                Write-Action1Debug (
                    "Retrying source organization '$sourceName' from existing " +
                    "map status '$($mapItem.status)'."
                )
            }
            else {
                $mapItem = & $newMapItem -SourceOrganization $sourceOrganization
                $mapItemsBySourceId[$sourceId] = $mapItem
                [void]$mapSourceOrder.Add($sourceId)
            }

            $mapItem.name = $sourceName
            $mapItem.description = $description
            $mapItem.imported_at = Get-UtcTimestamp

            $targetMatches = @()

            if ($targetOrganizationsByName.ContainsKey($sourceName)) {
                $targetMatches = @($targetOrganizationsByName[$sourceName])
            }

            if ($targetMatches.Count -gt 0) {
                Write-Action1Debug "Found $($targetMatches.Count) target organization match(es) for '$sourceName'."

                if ($ConflictAction -eq 'SkipExisting') {
                    $mapItem.id = $null
                    $mapItem.status = 'Skipped'
                    $skippedOrganizations++

                    Write-Action1Debug "Skipped source organization '$sourceName' because ConflictAction is SkipExisting."

                    if (-not $WhatIfPreference) {
                        & $saveMapFile
                    }

                    & $newResultObject `
                        -SourceId $sourceId `
                        -MapItem $mapItem `
                        -Message 'Target organization with the same name exists.'
                    continue
                }

                if ($ConflictAction -eq 'MergeExisting') {
                    if ($targetMatches.Count -gt 1) {
                        $mapItem.id = $null
                        $mapItem.status = 'Failed'
                        $failedOrganizations++

                        Write-Action1Debug (
                            "Failed merging source organization '$sourceName' " +
                            'because multiple target organizations have the same name.'
                        )

                        if (-not $WhatIfPreference) {
                            & $saveMapFile
                        }

                        & $newResultObject `
                            -SourceId $sourceId `
                            -MapItem $mapItem `
                            -Message 'Multiple target organizations with the same name exist.'
                        continue
                    }

                    $targetOrganization = $targetMatches[0]
                    $targetId = Get-FirstPropertyValue `
                        -InputObject $targetOrganization `
                        -PropertyName @('Org_ID', 'id', 'Id')

                    if ([string]::IsNullOrWhiteSpace($targetId)) {
                        $mapItem.id = $null
                        $mapItem.status = 'Failed'
                        $failedOrganizations++

                        if (-not $WhatIfPreference) {
                            & $saveMapFile
                        }

                        & $newResultObject `
                            -SourceId $sourceId `
                            -MapItem $mapItem `
                            -Message 'Target organization response did not contain an ID.'
                        continue
                    }

                    $targetLabel = (
                        "source organization '$sourceName' into target " +
                        "organization '$targetId' in '$resolvedMapPath'"
                    )

                    if (-not (& $confirmImportAction `
                        -Target $targetLabel `
                        -Action 'Merge source organization into existing target organization')) {
                        $mapItem.id = $null
                        $mapItem.status = 'Skipped'
                        $skippedOrganizations++

                        Write-Action1Debug "Skipped merging source organization '$sourceName'."

                        & $newResultObject `
                            -SourceId $sourceId `
                            -MapItem $mapItem `
                            -Message 'Organization merge was skipped.'
                        continue
                    }

                    try {
                        Write-Action1Debug "Updating target organization '$targetId' from '$sourceName'."

                        $updateParams = @{
                            OrgID        = $targetId
                            Name         = $sourceName
                            Confirm      = $false
                            ErrorAction  = 'Stop'
                        }

                        if (-not [string]::IsNullOrWhiteSpace($description)) {
                            $updateParams.Description = $description
                        }

                        $updatedOrganization = Update-Action1Organization @updateParams

                        if ($null -eq $updatedOrganization) {
                            throw "Update-Action1Organization returned no organization object."
                        }

                        $updatedName = Get-FirstPropertyValue `
                            -InputObject $updatedOrganization `
                            -PropertyName @('Org_Name', 'name', 'Name')
                        $updatedDescription = Get-FirstPropertyValue `
                            -InputObject $updatedOrganization `
                            -PropertyName @('Description', 'description')

                        if ([string]::IsNullOrWhiteSpace($updatedName)) {
                            $updatedName = $sourceName
                        }

                        if ($null -eq $updatedDescription) {
                            $updatedDescription = $description
                        }

                        $mapItem.id = $targetId
                        $mapItem.name = $updatedName
                        $mapItem.description = [string]$updatedDescription
                        $mapItem.status = 'Updated'
                        $updatedOrganizations++

                        Write-Action1Debug "Updated target organization '$updatedName' with id '$targetId'."

                        if (-not $WhatIfPreference) {
                            & $saveMapFile
                        }

                        & $newResultObject `
                            -SourceId $sourceId `
                            -MapItem $mapItem `
                            -Message 'Updated existing target organization.'
                        continue
                    }
                    catch {
                        $mapItem.id = $null
                        $mapItem.status = 'Failed'
                        $mapItem.imported_at = Get-UtcTimestamp
                        $failedOrganizations++

                        Write-Action1Debug (
                            "Failed updating target organization '$targetId'. " +
                            "Error: $($_.Exception.Message)"
                        )

                        if (-not $WhatIfPreference) {
                            & $saveMapFile
                        }

                        & $newResultObject `
                            -SourceId $sourceId `
                            -MapItem $mapItem `
                            -Message $_.Exception.Message
                        continue
                    }
                }
            }

            $targetLabel = "Action1 organization '$sourceName'"

            if (-not (& $confirmImportAction `
                -Target $targetLabel `
                -Action 'Create organization in target enterprise and write organization mapping')) {
                $mapItem.id = $null
                $mapItem.status = 'Skipped'
                $skippedOrganizations++

                Write-Action1Debug "Skipped creating source organization '$sourceName'."

                & $newResultObject `
                    -SourceId $sourceId `
                    -MapItem $mapItem `
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
                $targetDescription = Get-FirstPropertyValue `
                    -InputObject $createdOrganization `
                    -PropertyName @('Description', 'description')

                if ([string]::IsNullOrWhiteSpace($targetId)) {
                    throw 'Created organization response did not contain a target organization ID.'
                }

                if ([string]::IsNullOrWhiteSpace($targetName)) {
                    $targetName = $sourceName
                }

                if ($null -eq $targetDescription) {
                    $targetDescription = $description
                }

                $mapItem.id = $targetId
                $mapItem.name = $targetName
                $mapItem.description = [string]$targetDescription
                $mapItem.status = 'Created'
                $createdOrganizations++

                if (-not $targetOrganizationsByName.ContainsKey($targetName)) {
                    $targetOrganizationsByName[$targetName] = New-Object System.Collections.ArrayList
                }

                [void]$targetOrganizationsByName[$targetName].Add($createdOrganization)

                Write-Action1Debug "Created target organization '$targetName' with id '$targetId'."

                if (-not $WhatIfPreference) {
                    & $saveMapFile
                }

                & $newResultObject `
                    -SourceId $sourceId `
                    -MapItem $mapItem `
                    -Message 'Created target organization.'
            }
            catch {
                $mapItem.id = $null
                $mapItem.status = 'Failed'
                $mapItem.imported_at = Get-UtcTimestamp
                $failedOrganizations++

                Write-Action1Debug "Failed importing source organization '$sourceName'. Error: $($_.Exception.Message)"

                if (-not $WhatIfPreference) {
                    & $saveMapFile
                }

                & $newResultObject `
                    -SourceId $sourceId `
                    -MapItem $mapItem `
                    -Message $_.Exception.Message
            }
        }
    }
    finally {
        Write-Progress -Activity 'Importing Action1 organizations' -Completed
    }

    $summaryMessage = (
        "Organizations import completed. Total:{0}; created:{1}; updated:{2}; skipped:{3}; failed:{4}; map:'{5}'." -f
        $totalOrganizations,
        $createdOrganizations,
        $updatedOrganizations,
        $skippedOrganizations,
        $failedOrganizations,
        $resolvedMapPath
    )

    Write-Action1Debug $summaryMessage
    Write-Information $summaryMessage -InformationAction Continue
}
