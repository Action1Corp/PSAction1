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
        [switch]$Force
    )

    if ($Force.IsPresent) {
        $ConfirmPreference = 'None'
    }

    $sourcePath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path)
    $sourceJson = Read-JsonFile -Path $Path

    $sourceValidationMap = New-Action1JsonSchemaMap `
        -Schema $Script:Action1_OrganizationJsonSchema `
        -Type 'Organization'

    [void](Test-Action1JsonSchema `
        -Json $sourceJson `
        -ValidationMap $sourceValidationMap `
        -ObjectType "Source organizations file: $sourcePath")

    $sourceEnterpriseId = Get-FirstPropertyValue `
        -InputObject $sourceJson `
        -PropertyName @('enterprise_id')
    $sourceRegion = Get-FirstPropertyValue `
        -InputObject $sourceJson `
        -PropertyName @('region')

    try {
        [void](Test-Guid `
            -Guid $sourceEnterpriseId `
            -Label "Source enterprise ID '$sourceEnterpriseId'")
    }
    catch {
        Write-Error $_.Exception.Message -ErrorAction Stop
    }

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

    $resolvedMapPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($MapPath)
    $mapParentPath = Split-Path -Path $resolvedMapPath -Parent

    if (
        -not [string]::IsNullOrWhiteSpace($mapParentPath) -and
        -not (Test-Path -LiteralPath $mapParentPath)
    ) {
        Write-Action1Debug "Creating migration map directory '$mapParentPath'."

        if (-not $WhatIfPreference) {
            $null = New-Item -Path $mapParentPath -ItemType Directory -Force
        }
    }

    $newMappingFile = $false
    $mappingHeaderValues = [ordered]@{
        schema               = $Script:Action1_MappingJsonSchema
        datetime             = $null
        source_region        = $sourceRegion
        source_enterprise_id = $sourceEnterpriseId
        target_region        = $targetRegion
        target_enterprise_id = $targetEnterpriseId
    }

    if (Test-Path -LiteralPath $resolvedMapPath -PathType Leaf) {
        $mapping = Read-JsonFile -Path $resolvedMapPath
    }
    else {
        $newMappingFile = $true
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

    [void](Test-Action1JsonSchema `
        -Json $mapping `
        -ValidationMap $mapValidationMap `
        -ObjectType "Migration map '$resolvedMapPath'")

    if ($newMappingFile -and -not $WhatIfPreference) {
        Write-JsonFile -Path $resolvedMapPath -Json $mapping -Force
    }

    $items = @(
        $sourceJson.items |
            Where-Object { $null -ne $_ }
    )
    $totalCount = $items.Count
    $processedCount = 0
    $skippedCount = 0
    $failedCount = 0
    $createdCount = 0

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

        if (
            Test-Action1SourceMap `
                -MapObject $mapping `
                -SourceObjectId $sourceObjectId
        ) {
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

            $mapping | Add-Member `
                -MemberType NoteProperty `
                -Name $sourceObjectId `
                -Value $createdOrganization `
                -Force

            if (-not $WhatIfPreference) {
                Write-JsonFile -Path $resolvedMapPath -Json $mapping -Force
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

    Write-Progress `
        -Activity 'Import Action1 organizations from JSON' `
        -Completed

    [PSCustomObject][ordered]@{
        SourcePath    = $sourcePath
        MapPath       = $resolvedMapPath
        Processed     = $processedCount
        Skipped       = $skippedCount
        Created       = $createdCount
        Failed        = $failedCount
        SourceRegion  = Get-FirstPropertyValue `
            -InputObject $sourceJson `
            -PropertyName @('region')
        TargetRegion  = $targetRegion
        EnterpriseId  = $targetEnterpriseId
    }
}
