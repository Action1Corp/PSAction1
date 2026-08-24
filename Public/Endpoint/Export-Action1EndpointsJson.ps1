# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Export-Action1EndpointsJson {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateSet('Connected', 'Disconnected', 'Pending Uninstall', 'All')]
        [string]$Status = 'All',

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet('Yes', 'No', 'All')]
        [string]$RebootRequired = 'All',

        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateSet(
            'Windows 11',
            'Windows 10',
            'Windows Server',
            'macOS',
            'linux',
            'All'
        )]
        [string]$OS = 'All',

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

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

    $pathWasSpecified = $PSBoundParameters.ContainsKey('Path')

    if ($pathWasSpecified) {
        Write-Action1Debug "Starting endpoints JSON export to '$Path'."
    }
    else {
        Write-Action1Debug 'Starting endpoints JSON export.'
    }

    if (Initialize-Action1DefaultOrg) {
        $organizationId = Get-Action1DefaultOrgId
    }

    $region = Get-Action1Region
    $enterpriseId = Get-Action1EnterpriseId -ErrorAction Stop

    if (-not $pathWasSpecified) {
        $orgName = Get-Action1DefaultOrgName
        $normalizedOrgName = ConvertTo-LatinAlphaNumericString -InputString $orgName

        if ([string]::IsNullOrWhiteSpace($normalizedOrgName)) {
            Write-Action1Debug 'Default organization name is empty after normalization.'
            $normalizedOrgName = $organizationId
        }

        $fileNameFormat = $Script:Action1_EndpointsExportFileNameTemplate `
            -f $normalizedOrgName, '{0}'
        $fileName = New-ExportFileName `
            -FileNameFormat $fileNameFormat `
            -TimestampTemplate $Script:Action1_ExportFileNameTimestampTemplate
        $Path = Join-Path -Path (Get-Location) -ChildPath $fileName
    }

    $resolvedPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path)
    $parentPath = Split-Path -Path $resolvedPath -Parent

    if (
        (Test-Path -LiteralPath $resolvedPath -PathType Leaf) -and
        -not $Force.IsPresent
    ) {
        $message = "The JSON export file '$resolvedPath' already exists. "
        $message += 'Use -Force to overwrite it.'
        throw $message
    }

    if (
        -not [string]::IsNullOrWhiteSpace($parentPath) -and
        -not (Test-Path -LiteralPath $parentPath)
    ) {
        Write-Action1Debug "Creating export directory '$parentPath'."
        $null = New-Item -Path $parentPath -ItemType Directory -Force
    }

    $getEndpointsParams = @{
        Status         = $Status
        RebootRequired = $RebootRequired
        OS             = $OS
        AsPage         = $true
        Limit          = $PageSize
        ErrorAction    = 'Stop'
    }

    $jsonContentParams = @{
        Path = $resolvedPath
    }

    if ($Force.IsPresent) {
        $jsonContentParams.Force = $true
    }

    $headerLines = @(
        '{',
        ('  "schema": {0},' -f (ConvertTo-JsonValue $Script:Action1_EndpointJsonSchema)),
        ('  "datetime": {0},' -f (ConvertTo-JsonValue (Get-UtcTimestamp))),
        ('  "region": {0},' -f (ConvertTo-JsonValue $region)),
        ('  "enterprise_id": {0},' -f (ConvertTo-JsonValue $enterpriseId)),
        ('  "organization_id": {0},' -f (ConvertTo-JsonValue $organizationId)),
        '  "type": "Endpoint",',
        '  "items": ['
    )

    Write-TextFileContent @jsonContentParams -Content $headerLines

    $exportedCount = 0
    $exportedEndpointIds = @{}
    $pendingJsonLines = $null

    foreach ($page in Get-Action1Endpoints @getEndpointsParams) {
        $endpointsToExport = @(
            $page.Items |
                Where-Object { $null -ne $_ }
        )

        foreach ($endpoint in $endpointsToExport) {
            $endpointId = ([string]$endpoint.id).Trim()

            if (-not [string]::IsNullOrWhiteSpace($endpointId)) {
                if ($exportedEndpointIds.ContainsKey($endpointId)) {
                    Write-Action1Debug "Skipping duplicate endpoint '$endpointId'."
                    continue
                }

                $exportedEndpointIds[$endpointId] = $true
            }

            $jsonItem = $endpoint |
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

    $message = "Exported $exportedCount endpoint record(s) "
    $message += "to '$resolvedPath'."
    Write-Action1Debug $message
}
