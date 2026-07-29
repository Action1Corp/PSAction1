# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Export-Action1OrganizationsCsv {
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
        $timestamp = Get-Date -Format 'yyMMdd_HHmm'
        $fileName = 'Action1_Organizations_{0}.csv' -f $timestamp
        $Path = Join-Path -Path (Get-Location) -ChildPath $fileName
    }

    Write-Action1Debug "Starting organizations CSV export to '$Path'."

    $resolvedPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path)
    $parentPath = Split-Path -Path $resolvedPath -Parent

    if (-not [string]::IsNullOrWhiteSpace($parentPath) -and -not (Test-Path -LiteralPath $parentPath)) {
        Write-Action1Debug "Creating export directory '$parentPath'."
        $null = New-Item -Path $parentPath -ItemType Directory -Force
    }

    $organizations = @(Get-Action1Organizations -ErrorAction Stop)

    $organizationList = @(
        $organizations |
            Where-Object { $null -ne $_ }
    )

    if ($organizationList.Count -eq 0) {
        Write-Error 'No Action1 organizations were returned for CSV export.' -ErrorAction Stop
    }

    $region = Get-Action1Region

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

    $exportColumns = @(
        'Id',
        'Name',
        'Description',
        'EntityType',
        'EnterpriseId',
        'Region',
        'ExportedAt'
    )
    $header = $exportColumns -join ','

    $setContentParams = @{
        LiteralPath = $resolvedPath
        Value       = $header
        Encoding    = 'UTF8'
    }

    if ($Force.IsPresent) {
        $setContentParams.Force = $true
    }

    try {
        Set-Content @setContentParams -ErrorAction Stop
    }
    catch {
        throw "Unable to initialize CSV file '$resolvedPath'. Close the file if it is open in another application, verify write permissions, or use -Force for read-only/hidden files. Error: $($_.Exception.Message)"
    }

    Write-Action1Debug "Initialized CSV file '$resolvedPath'."

    $totalRowsExported = 0

    foreach ($organization in $organizationsToExport) {
        $exportedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd_HH-mm-ss')

        $csvRow = [PSCustomObject][ordered]@{
            Id           = $organization.Org_ID
            Name         = $organization.Org_Name
            Description  = $organization.Description
            EntityType   = $organization.Type
            EnterpriseId = $organization.EnterpriseId
            Region       = $region
            ExportedAt   = $exportedAt
        }

        $csvFields = foreach ($column in $exportColumns) {
            $value = $csvRow.$column

            if ($null -eq $value) {
                ''
            }
            else {
                $stringValue = [string]$value

                if ($stringValue -match '[,"\r\n]') {
                    '"{0}"' -f ($stringValue -replace '"', '""')
                }
                else {
                    $stringValue
                }
            }
        }

        $csvLine = $csvFields -join ','

        $addContentParams = @{
            LiteralPath = $resolvedPath
            Value       = $csvLine
            Encoding    = 'UTF8'
        }

        if ($Force.IsPresent) {
            $addContentParams.Force = $true
        }

        Add-Content @addContentParams -ErrorAction Stop
        $totalRowsExported++
        Write-Action1Debug "Appended organization '$($organization.Org_Name)' to '$resolvedPath'."
    }

    Write-Action1Debug "Exported $totalRowsExported organization record(s) to '$resolvedPath'."
}
