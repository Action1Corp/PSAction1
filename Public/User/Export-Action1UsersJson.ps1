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
        -not [string]::IsNullOrWhiteSpace($parentPath) -and
        -not (Test-Path -LiteralPath $parentPath)
    ) {
        Write-Action1Debug "Creating export directory '$parentPath'."
        $null = New-Item -Path $parentPath -ItemType Directory -Force
    }

    $userList = @(
        Get-Action1Users -ErrorAction Stop |
            Where-Object { $null -ne $_ }
    )

    $usersToExport = @(
        $userList |
            Where-Object {
                if ($PSCmdlet.ParameterSetName -eq 'ByUserIds') {
                    $userIdsToMatch = @(
                        $UserIds |
                            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                            ForEach-Object { ([string]$_).Trim() }
                    )
                    $userId = ([string]$_.id).Trim()
                    $userIdsToMatch -icontains $userId
                }
                else {
                    $true
                }
            }
    )

    $jsonExport = [PSCustomObject][ordered]@{
        schema          = $Script:Action1_UserJsonSchema
        datetime        = Get-UtcTimestamp
        region          = $region
        enterprise_id   = $enterpriseId
        organization_id = $organizationId
        type            = 'User'
        items           = $usersToExport
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

    $message = "Exported $($usersToExport.Count) user record(s) "
    $message += "to '$resolvedPath'."
    Write-Action1Debug $message
}
