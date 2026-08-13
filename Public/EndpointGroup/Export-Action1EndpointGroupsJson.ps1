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

    $endpointGroupList = @(
        Get-Action1EndpointGroups -ErrorAction Stop |
            Where-Object { $null -ne $_ }
    )

    $region = Get-Action1Region
    $enterpriseId = Get-Action1EnterpriseId -ErrorAction Stop
    $organizationId = Get-Action1DefaultOrgId -ErrorAction Stop

    $endpointGroupsToExport = @(
        $endpointGroupList |
            Where-Object {
                if ($PSCmdlet.ParameterSetName -eq 'ByEndpointGroupIds') {
                    $endpointGroupIdsToMatch = @(
                        $EndpointGroupIds |
                            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                            ForEach-Object { ([string]$_).Trim() }
                    )
                    $endpointGroupId = ([string]$_.id).Trim()
                    $endpointGroupIdsToMatch -icontains $endpointGroupId
                }
                elseif ($PSCmdlet.ParameterSetName -eq 'ByEndpointGroupNames') {
                    $endpointGroupNamesToMatch = @(
                        $EndpointGroupNames |
                            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                            ForEach-Object { ([string]$_).Trim() }
                    )
                    $endpointGroupName = ([string]$_.name).Trim()
                    $endpointGroupNamesToMatch -icontains $endpointGroupName
                }
                else {
                    $true
                }
            }
    )

    $jsonExport = [PSCustomObject][ordered]@{
        schema          = $Script:Action1_EndpointGroupJsonSchema
        datetime        = Get-UtcTimestamp
        region          = $region
        enterprise_id   = $enterpriseId
        organization_id = $organizationId
        type            = 'EndpointGroup'
        items           = $endpointGroupsToExport
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
        $message = "Unable to write JSON file '$resolvedPath'. Close the file if it is "
        $message += 'open in another application, verify write permissions, or use '
        $message += "-Force for read-only/hidden files. Error: $($_.Exception.Message)"
        throw $message
    }

    $message = "Exported $($endpointGroupsToExport.Count) endpoint group record(s) "
    $message += "to '$resolvedPath'."
    Write-Action1Debug $message
}
