# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Export-Action1OrganizationsJson {
    [CmdletBinding(DefaultParameterSetName = 'AllOrganizations')]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $false, ParameterSetName = 'ByOrgIds')]
        [ValidateScript({
            if (-not (Test-Guid $_)) {
                throw 'OrgID must use the standard GUID format.'
            }

            $true
        })]
        [string[]]$OrgIds,

        [Parameter(Mandatory = $false, ParameterSetName = 'ByOrgNames')]
        [string[]]$OrgNames,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    if (-not $PSBoundParameters.ContainsKey('Path')) {
        $fileName = New-ExportFileName `
            -FileNameFormat $Script:Action1_OrgExportFileNameTemplate `
            -TimestampTemplate $Script:Action1_ExportFileNameTimestampTemplate
        $Path = Join-Path -Path (Get-Location) -ChildPath $fileName
    }

    Write-Action1Debug "Starting organizations JSON export to '$Path'."

    $resolvedPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path)
    $parentPath = Split-Path -Path $resolvedPath -Parent

    if (
        -not [string]::IsNullOrWhiteSpace($parentPath) -and
        -not (Test-Path -LiteralPath $parentPath)
    ) {
        Write-Action1Debug "Creating export directory '$parentPath'."
        $null = New-Item -Path $parentPath -ItemType Directory -Force
    }

    $organizations = @(Get-Action1Organizations -ErrorAction Stop)

    $organizationList = @(
        $organizations |
            Where-Object { $null -ne $_ }
    )

    if ($organizationList.Count -eq 0) {
        $message = 'No Action1 organizations were returned for JSON export.'
        Write-Error $message -ErrorAction Stop
    }

    $region = Get-Action1Region
    $enterpriseId = Get-Action1EnterpriseId -ErrorAction Stop

    $organizationsToExport = @(
        $organizationList |
            Where-Object {
                if ($PSCmdlet.ParameterSetName -eq 'ByOrgIds') {
                    $orgIdsToMatch = @(
                        $OrgIds |
                            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                            ForEach-Object { ([string]$_).Trim() }
                    )
                    $organizationId = ([string]$_.Org_ID).Trim()
                    $orgIdsToMatch -icontains $organizationId
                }
                elseif ($PSCmdlet.ParameterSetName -eq 'ByOrgNames') {
                    $orgNamesToMatch = @(
                        $OrgNames |
                            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                            ForEach-Object { ([string]$_).Trim() }
                    )
                    $organizationName = ([string]$_.Org_Name).Trim()
                    $orgNamesToMatch -icontains $organizationName
                }
                else {
                    $true
                }
            }
    )

    $baseUri = ([string]$Script:Action1_BaseURI).TrimEnd('/')

    $jsonOrganizations = @(
        foreach ($organization in $organizationsToExport) {
            $organizationId = ([string]$organization.Org_ID).Trim()
            $organizationName = [string]$organization.Org_Name
            $organizationDescription = ''

            if ($null -ne $organization.Description) {
                $organizationDescription = [string]$organization.Description
            }

            $organizationType = [string]$organization.Type

            if ([string]::IsNullOrWhiteSpace($organizationType)) {
                $organizationType = 'Organization'
            }

            $organizationEnterpriseId = [string]$organization.EnterpriseId
            $selfUri = ''

            if (
                -not [string]::IsNullOrWhiteSpace($baseUri) -and
                -not [string]::IsNullOrWhiteSpace($organizationId)
            ) {
                $selfUri = '{0}/organizations/{1}' -f $baseUri, $organizationId
            }

            [PSCustomObject][ordered]@{
                id            = $organizationId
                type          = $organizationType
                self          = $selfUri
                name          = $organizationName
                description   = $organizationDescription
                enterprise_id = $organizationEnterpriseId
            }
        }
    )

    $jsonExport = [PSCustomObject][ordered]@{
        schema        = $Script:Action1_OrganizationJsonSchema
        datetime      = Get-UtcTimestamp
        region        = $region
        enterprise_id = $enterpriseId
        type          = 'Organization'
        items         = $jsonOrganizations
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

    $message = "Exported $($jsonOrganizations.Count) organization record(s) "
    $message += "to '$resolvedPath'."
    Write-Action1Debug $message
}
