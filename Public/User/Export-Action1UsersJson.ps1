# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Export-Action1UsersJson {
    [CmdletBinding(DefaultParameterSetName = 'AllUsers')]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $false, ParameterSetName = 'ByUserIds')]
        [ValidateScript({
            Test-Guid -Guid $_ -Label 'UserId'
        })]
        [string[]]$UserIds,

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
            -FileNameFormat $Script:Action1_UsersExportFileNameTemplate `
            -TimestampTemplate $Script:Action1_ExportFileNameTimestampTemplate
        $Path = Join-Path -Path (Get-Location) -ChildPath $fileName
    }

    Write-Action1Debug "Starting users JSON export to '$Path'."

    if (Initialize-Action1DefaultOrg) {
        $organizationId = Get-Action1DefaultOrgId
    }

    $region = Get-Action1Region
    $enterpriseId = Get-Action1EnterpriseId -ErrorAction Stop

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

    $userIdsToMatch = @(
        if ($PSCmdlet.ParameterSetName -eq 'ByUserIds') {
            $UserIds |
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

    $testUserFilter = {
        param(
            [object]$User
        )

        if ($PSCmdlet.ParameterSetName -eq 'ByUserIds') {
            $userId = ([string]$User.id).Trim()
            return ($userIdsToMatch -icontains $userId)
        }

        return $true
    }

    $headerLines = @(
        '{',
        ('  "schema": {0},' -f (ConvertTo-JsonValue $Script:Action1_UserJsonSchema)),
        ('  "datetime": {0},' -f (ConvertTo-JsonValue (Get-UtcTimestamp))),
        ('  "region": {0},' -f (ConvertTo-JsonValue $region)),
        ('  "enterprise_id": {0},' -f (ConvertTo-JsonValue $enterpriseId)),
        ('  "organization_id": {0},' -f (ConvertTo-JsonValue $organizationId)),
        '  "type": "User",',
        '  "items": ['
    )

    Write-TextFileContent @jsonContentParams -Content $headerLines

    $exportedCount = 0
    $exportedUserIds = @{}
    $pendingJsonLines = $null

    foreach ($page in Get-Action1Users -AsPage -Limit $PageSize -ErrorAction Stop) {
        $usersToExport = @(
            $page.Items |
                Where-Object { $null -ne $_ } |
                Where-Object { & $testUserFilter $_ }
        )

        foreach ($user in $usersToExport) {
            $userId = ([string]$user.id).Trim()

            if (-not [string]::IsNullOrWhiteSpace($userId)) {
                if ($exportedUserIds.ContainsKey($userId)) {
                    Write-Action1Debug "Skipping duplicate user '$userId'."
                    continue
                }

                $exportedUserIds[$userId] = $true
            }

            $jsonItem = $user |
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

    $message = "Exported $exportedCount user record(s) "
    $message += "to '$resolvedPath'."
    Write-Action1Debug $message
}
