# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Export-Action1EndpointGroupMembersJson {
    [CmdletBinding(DefaultParameterSetName = 'ByGroupId')]
    param(
        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'ByGroupId',
            Position = 0
        )]
        [ValidateNotNullOrEmpty()]
        [string]$GroupId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByGroupName')]
        [ValidateNotNullOrEmpty()]
        [string]$GroupName,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Connected', 'Disconnected', 'Pending Uninstall', 'All')]
        [string]$Status = 'All',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Yes', 'No', 'All')]
        [string]$RebootRequired = 'All',

        [Parameter(Mandatory = $false)]
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
        Write-Action1Debug "Starting endpoint group members JSON export to '$Path'."
    }
    else {
        Write-Action1Debug 'Starting endpoint group members JSON export.'
    }

    if (Initialize-Action1DefaultOrg) {
        $organizationId = Get-Action1DefaultOrgId
    }

    $region = Get-Action1Region
    $enterpriseId = Get-Action1EnterpriseId -ErrorAction Stop

    if ($PSCmdlet.ParameterSetName -eq 'ByGroupName') {
        $endpointGroup = Resolve-Action1EndpointGroupByName -GroupName $GroupName
    }
    else {
        $endpointGroup = Resolve-Action1EndpointGroupById -GroupId $GroupId
    }

    $resolvedGroupId = ([string]$endpointGroup.id).Trim()

    if ([string]::IsNullOrWhiteSpace($resolvedGroupId)) {
        Write-Error 'Endpoint group object does not contain an id.' -ErrorAction Stop
    }

    if (-not $pathWasSpecified) {
        $orgName = Get-Action1DefaultOrgName
        $normalizedOrgName = ConvertTo-LatinAlphaNumericString -InputString $orgName

        if ([string]::IsNullOrWhiteSpace($normalizedOrgName)) {
            Write-Action1Debug 'Default organization name is empty after normalization.'
            $normalizedOrgName = $organizationId
        }

        $endpointGroupIdFileNamePart = $resolvedGroupId

        foreach ($invalidCharacter in [System.IO.Path]::GetInvalidFileNameChars()) {
            $invalidCharacterValue = [string]$invalidCharacter
            $endpointGroupIdFileNamePart =
                $endpointGroupIdFileNamePart.Replace($invalidCharacterValue, '')
        }

        if ([string]::IsNullOrWhiteSpace($endpointGroupIdFileNamePart)) {
            Write-Action1Debug 'Endpoint group ID is empty after file name cleanup.'
            $endpointGroupIdFileNamePart = 'EndpointGroup'
        }

        $fileNameFormat = $Script:Action1_EndpointGroupMembersExportFileNameTemplate `
            -f $normalizedOrgName, $endpointGroupIdFileNamePart, '{0}'
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

    $getGroupEndpointsParams = @{
        Status         = $Status
        RebootRequired = $RebootRequired
        OS             = $OS
        ErrorAction    = 'Stop'
    }

    if ($PSCmdlet.ParameterSetName -eq 'ByGroupName') {
        $getGroupEndpointsParams.GroupName = $GroupName
    }
    else {
        $getGroupEndpointsParams.GroupId = $GroupId
    }

    Write-Action1Debug "Getting endpoints in endpoint group '$resolvedGroupId'."

    $endpointMembers = @(
        Get-Action1GroupEndpoints @getGroupEndpointsParams |
            Where-Object { $null -ne $_ }
    )

    $jsonExport = [PSCustomObject][ordered]@{
        schema           = $Script:Action1_EndpointJsonSchema
        datetime         = Get-UtcTimestamp
        region           = $region
        enterprise_id    = $enterpriseId
        organization_id  = $organizationId
        endpointgroup_id = $resolvedGroupId
        type             = 'Endpoint'
        items            = $endpointMembers
    }

    $jsonContent = $jsonExport | ConvertTo-Json -Depth 10

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
        $message = "Unable to write JSON file '$resolvedPath'. Close the file if it is "
        $message += 'open in another application, verify write permissions, or use '
        $message += "-Force for read-only/hidden files. Error: $($_.Exception.Message)"
        throw $message
    }

    $message = "Exported $($endpointMembers.Count) endpoint group member record(s) "
    $message += "for endpoint group '$resolvedGroupId' to '$resolvedPath'."
    Write-Action1Debug $message
}
