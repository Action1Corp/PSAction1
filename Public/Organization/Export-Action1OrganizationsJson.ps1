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
            Test-Guid -Guid $_ -Label 'OrgID'
        })]
        [string[]]$OrgIds,

        [Parameter(Mandatory = $false, ParameterSetName = 'ByOrgNames')]
        [string[]]$OrgNames,

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

    $region = Get-Action1Region
    $enterpriseId = Get-Action1EnterpriseId -ErrorAction Stop

    $orgIdsToMatch = @(
        if ($PSCmdlet.ParameterSetName -eq 'ByOrgIds') {
            $OrgIds |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                ForEach-Object { ([string]$_).Trim() }
        }
    )

    $orgNamesToMatch = @(
        if ($PSCmdlet.ParameterSetName -eq 'ByOrgNames') {
            $OrgNames |
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

    $testOrganizationFilter = {
        param(
            [object]$Organization
        )

        if ($PSCmdlet.ParameterSetName -eq 'ByOrgIds') {
            $organizationId = ([string]$Organization.Org_ID).Trim()
            return ($orgIdsToMatch -icontains $organizationId)
        }

        if ($PSCmdlet.ParameterSetName -eq 'ByOrgNames') {
            $organizationName = ([string]$Organization.Org_Name).Trim()
            return ($orgNamesToMatch -icontains $organizationName)
        }

        return $true
    }

    $headerLines = @(
        '{',
        ('  "schema": {0},' -f (ConvertTo-JsonValue $Script:Action1_OrganizationJsonSchema)),
        ('  "datetime": {0},' -f (ConvertTo-JsonValue (Get-UtcTimestamp))),
        ('  "region": {0},' -f (ConvertTo-JsonValue $region)),
        ('  "enterprise_id": {0},' -f (ConvertTo-JsonValue $enterpriseId)),
        '  "type": "Organization",',
        '  "items": ['
    )

    Write-TextFileContent @jsonContentParams -Content $headerLines

    $organizationCount = 0
    $exportedCount = 0
    $exportedOrganizationIds = @{}
    $pendingJsonLines = $null

    foreach (
        $page in Get-Action1Organizations -AsPage -Limit $PageSize -ErrorAction Stop
    ) {
        $organizationsToExport = @(
            $page.Items |
                Where-Object { $null -ne $_ } |
                ForEach-Object {
                    $organizationCount++
                    $_
                } |
                Where-Object { & $testOrganizationFilter $_ }
        )

        foreach ($organization in $organizationsToExport) {
            $organizationId = ([string]$organization.Org_ID).Trim()

            if (-not [string]::IsNullOrWhiteSpace($organizationId)) {
                if ($exportedOrganizationIds.ContainsKey($organizationId)) {
                    Write-Action1Debug "Skipping duplicate organization '$organizationId'."
                    continue
                }

                $exportedOrganizationIds[$organizationId] = $true
            }

            $organizationItem = ConvertTo-Action1OrganizationItem `
                -Organization $organization
            $jsonItem = $organizationItem |
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

    if ($organizationCount -eq 0) {
        $message = 'No Action1 organizations were returned for JSON export.'
        Write-Error $message -ErrorAction Stop
    }

    $message = "Exported $exportedCount organization record(s) "
    $message += "to '$resolvedPath'."
    Write-Action1Debug $message
}
