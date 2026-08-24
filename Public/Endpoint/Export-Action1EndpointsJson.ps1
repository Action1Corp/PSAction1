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
        ErrorAction    = 'Stop'
    }

    $endpoints = @(
        Get-Action1Endpoints @getEndpointsParams |
            Where-Object { $null -ne $_ }
    )

    $jsonExport = [PSCustomObject][ordered]@{
        schema          = $Script:Action1_EndpointJsonSchema
        datetime        = Get-UtcTimestamp
        region          = $region
        enterprise_id   = $enterpriseId
        organization_id = $organizationId
        type            = 'Endpoint'
        items           = $endpoints
    }

    $jsonContent = $jsonExport |
        ConvertTo-Json -Depth $Script:Action1_JsonObjectConversionDepth

    $setContentParams = @{
        LiteralPath = $resolvedPath
        Value       = $jsonContent
        Encoding    = 'UTF8'
    }

    if ($Force.IsPresent) {
        $setContentParams.Force = $true
    }

    try {
        Set-Content @setContentParams -ErrorAction Stop
    }
    catch {
        $message = New-TextFileWriteErrorMessage `
            -Operation 'write JSON file' `
            -Path $resolvedPath `
            -ErrorMessage $_.Exception.Message

        throw $message
    }

    $message = "Exported $($endpoints.Count) endpoint record(s) "
    $message += "to '$resolvedPath'."
    Write-Action1Debug $message
}
