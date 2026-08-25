# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Export-Action1UserRolesJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            Test-Guid -Guid $_ -Label 'UserId'
        })]
        [string]$UserId,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    if (-not $PSBoundParameters.ContainsKey('Path')) {
        $userIdFileNamePart = ([string]$UserId).Trim()
        $fileNameFormat = $Script:Action1_UserRolesExportFileNameTemplate `
            -f $userIdFileNamePart, '{0}'
        $fileName = New-ExportFileName `
            -FileNameFormat $fileNameFormat `
            -TimestampTemplate $Script:Action1_ExportFileNameTimestampTemplate
        $Path = Join-Path -Path (Get-Location) -ChildPath $fileName
    }

    Write-Action1Debug "Starting user roles JSON export to '$Path'."

    if (Initialize-Action1DefaultOrg) {
        $organizationId = Get-Action1DefaultOrgId
    }

    $region = Get-Action1Region
    $enterpriseId = Get-Action1EnterpriseId -ErrorAction Stop

    $resolvedPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path)
    $parentPath = Split-Path -Path $resolvedPath -Parent

    $null = Test-Action1ExportFile `
        -Path $resolvedPath `
        -FileType 'JSON' `
        -Force:$Force.IsPresent

    if (
        -not [string]::IsNullOrWhiteSpace($parentPath) -and
        -not (Test-Path -LiteralPath $parentPath)
    ) {
        Write-Action1Debug "Creating export directory '$parentPath'."
        $null = New-Item -Path $parentPath -ItemType Directory -Force
    }

    $userRoles = @(
        Get-Action1UserRoles -UserId $UserId -ErrorAction Stop |
            Where-Object { $null -ne $_ }
    )

    $jsonExport = [PSCustomObject][ordered]@{
        schema          = $Script:Action1_RoleJsonSchema
        datetime        = Get-UtcTimestamp
        region          = $region
        enterprise_id   = $enterpriseId
        organization_id = $organizationId
        user_id         = $UserId
        type            = 'Role'
        items           = $userRoles
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
        $message += "-Force to overwrite existing or read-only/hidden files. "
        $message += "Error: $($_.Exception.Message)"
        throw $message
    }

    $message = "Exported $($userRoles.Count) user role record(s) "
    $message += "for user '$UserId' to '$resolvedPath'."
    Write-Action1Debug $message
}
