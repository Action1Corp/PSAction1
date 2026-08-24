# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Export-Action1EndpointGroupsJson {
    [CmdletBinding(DefaultParameterSetName = 'AllEndpointGroups')]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $false, ParameterSetName = 'ByEndpointGroupIds')]
        [string[]]$EndpointGroupIds,

        [Parameter(Mandatory = $false, ParameterSetName = 'ByEndpointGroupNames')]
        [string[]]$EndpointGroupNames,

        [Parameter(Mandatory = $false)]
        [ValidateScript({
            Test-Action1PageSize `
                -Value $_ `
                -Maximum $Script:Action1_ExportPageSize `
                -ParameterName 'PageSize'
        })]
        [int]$PageSize = [int]$Script:Action1_ExportPageSize,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    if (-not $PSBoundParameters.ContainsKey('Path')) {
        $orgName = Get-Action1DefaultOrgName
        $orgId = Get-Action1DefaultOrgId
        $normalizedOrgName = ConvertTo-LatinAlphaNumericString -InputString $orgName

        if ([string]::IsNullOrWhiteSpace($normalizedOrgName)) {
            Write-Action1Debug 'Default organization name is empty after normalization.'
            $normalizedOrgName = $orgId
        }

        $fileNameFormat = $Script:Action1_EndpointGroupsExportFileNameTemplate `
            -f $normalizedOrgName, '{0}'
        $fileName = New-ExportFileName `
            -FileNameFormat $fileNameFormat `
            -TimestampTemplate $Script:Action1_ExportFileNameTimestampTemplate
        $Path = Join-Path -Path (Get-Location) -ChildPath $fileName
    }

    Write-Action1Debug "Starting endpoint groups JSON export to '$Path'."

    $resolvedPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path)
    $parentPath = Split-Path -Path $resolvedPath -Parent

    if (
        -not [string]::IsNullOrWhiteSpace($parentPath) -and
        -not (Test-Path -LiteralPath $parentPath)
    ) {
        Write-Action1Debug "Creating export directory '$parentPath'."
        $null = New-Item -Path $parentPath -ItemType Directory -Force
    }

    $region = Get-Action1Region
    $enterpriseId = Get-Action1EnterpriseId -ErrorAction Stop
    $organizationId = Get-Action1DefaultOrgId -ErrorAction Stop

    $endpointGroupIdsToMatch = @(
        if ($PSCmdlet.ParameterSetName -eq 'ByEndpointGroupIds') {
            $EndpointGroupIds |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                ForEach-Object { ([string]$_).Trim() }
        }
    )

    $endpointGroupNamesToMatch = @(
        if ($PSCmdlet.ParameterSetName -eq 'ByEndpointGroupNames') {
            $EndpointGroupNames |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                ForEach-Object { ([string]$_).Trim() }
        }
    )

    $jsonContentParams = @{
        Path = $resolvedPath
    }

    if ($Force.IsPresent) {
        $jsonContentParams.Force = $true
    }

    $testEndpointGroupFilter = {
        param(
            [object]$EndpointGroup
        )

        if ($PSCmdlet.ParameterSetName -eq 'ByEndpointGroupIds') {
            $endpointGroupId = ([string]$EndpointGroup.id).Trim()
            return ($endpointGroupIdsToMatch -icontains $endpointGroupId)
        }

        if ($PSCmdlet.ParameterSetName -eq 'ByEndpointGroupNames') {
            $endpointGroupName = ([string]$EndpointGroup.name).Trim()
            return ($endpointGroupNamesToMatch -icontains $endpointGroupName)
        }

        return $true
    }

    $headerLines = @(
        '{',
        ('  "schema": {0},' -f (ConvertTo-JsonValue $Script:Action1_EndpointGroupJsonSchema)),
        ('  "datetime": {0},' -f (ConvertTo-JsonValue (Get-UtcTimestamp))),
        ('  "region": {0},' -f (ConvertTo-JsonValue $region)),
        ('  "enterprise_id": {0},' -f (ConvertTo-JsonValue $enterpriseId)),
        ('  "organization_id": {0},' -f (ConvertTo-JsonValue $organizationId)),
        '  "type": "EndpointGroup",',
        '  "items": ['
    )

    Write-TextFileContent @jsonContentParams -Content $headerLines

    $exportedCount = 0
    $exportedEndpointGroupIds = @{}
    $pendingJsonLines = $null

    foreach (
        $page in Get-Action1EndpointGroups -AsPage -Limit $PageSize -ErrorAction Stop
    ) {
        $endpointGroupsToExport = @(
            $page.Items |
                Where-Object { $null -ne $_ } |
                Where-Object { & $testEndpointGroupFilter $_ }
        )

        foreach ($endpointGroup in $endpointGroupsToExport) {
            $endpointGroupId = ([string]$endpointGroup.id).Trim()

            if (-not [string]::IsNullOrWhiteSpace($endpointGroupId)) {
                if ($exportedEndpointGroupIds.ContainsKey($endpointGroupId)) {
                    Write-Action1Debug "Skipping duplicate endpoint group '$endpointGroupId'."
                    continue
                }

                $exportedEndpointGroupIds[$endpointGroupId] = $true
            }

            $jsonItem = $endpointGroup |
                ConvertTo-Json -Depth $Script:Action1_JsonObjectConversionDepth
            $jsonLines = @($jsonItem -split "`r?`n")

            $indentedJsonLines = @(
                $jsonLines |
                    ForEach-Object { '    {0}' -f $_ }
            )

            if ($null -ne $pendingJsonLines) {
                $previousJsonLines = @($pendingJsonLines)
                $previousJsonLines[$previousJsonLines.Count - 1] += ','
                Write-TextFileContent @jsonContentParams -Content $previousJsonLines -Append
            }

            $pendingJsonLines = $indentedJsonLines
            $exportedCount++
        }
    }

    if ($null -ne $pendingJsonLines) {
        Write-TextFileContent @jsonContentParams -Content $pendingJsonLines -Append
    }

    $footerLines = @(
        '  ]',
        '}'
    )

    Write-TextFileContent @jsonContentParams -Content $footerLines -Append

    $message = "Exported $exportedCount endpoint group record(s) "
    $message += "to '$resolvedPath'."
    Write-Action1Debug $message
}
