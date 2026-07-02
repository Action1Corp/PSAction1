# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Get-Action1Endpoints {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [ValidateSet('', 'Connected', 'Disconnected', 'Pending Uninstall')]
        [string]$Status = 'Disconnected',
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [ValidateSet('', 'SUCCESS', 'WARNING', 'ERROR', 'UNDEFINED')]
        [string]$Online_Status,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [ValidateSet('', 'SUCCESS', 'WARNING', 'ERROR', 'UNDEFINED')]
        [string]$Updater_Status,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [ValidateSet('', 'SUCCESS', 'WARNING', 'ERROR', 'UNDEFINED')]
        [string]$Vulnerability_Status
    )

    if (Initialize-Action1DefaultOrg) {
        $orgId = Get-Action1DefaultOrgId
    }

    if (-not $Script:Action1_UriMap.ContainsKey('G_Endpoints')) {
        throw "Action1 URI map key 'G_Endpoints' is not defined."
    }

    $endpoint = & $Script:Action1_UriMap['G_Endpoints'] $orgId
    $path = "$Script:Action1_BaseURI{0}" -f $endpoint
    $addArgs = $null
    $debugFilters = @()

    if (-not [string]::IsNullOrWhiteSpace($Status)) {
        $encodedStatus = [System.Uri]::EscapeDataString($Status)
        $queryArgument = "status=$encodedStatus"
        $addArgs = Join-QueryString -QueryString $addArgs -Argument $queryArgument
        $debugFilters += "status '$Status'"
    }

    if (-not [string]::IsNullOrWhiteSpace($Online_Status)) {
        $encodedOnlineStatus = [System.Uri]::EscapeDataString($Online_Status)
        $queryArgument = "online_status=$encodedOnlineStatus"
        $addArgs = Join-QueryString -QueryString $addArgs -Argument $queryArgument
        $debugFilters += "online status '$Online_Status'"
    }

    if (-not [string]::IsNullOrWhiteSpace($Updater_Status)) {
        $encodedUpdaterStatus = [System.Uri]::EscapeDataString($Updater_Status)
        $queryArgument = "updater_status=$encodedUpdaterStatus"
        $addArgs = Join-QueryString -QueryString $addArgs -Argument $queryArgument
        $debugFilters += "updater status '$Updater_Status'"
    }

    if (-not [string]::IsNullOrWhiteSpace($Vulnerability_Status)) {
        $encodedVulnStatus = [System.Uri]::EscapeDataString($Vulnerability_Status)
        $queryArgument = "vulnerability_status=$encodedVulnStatus"
        $addArgs = Join-QueryString -QueryString $addArgs -Argument $queryArgument
        $debugFilters += "vulnerability status '$Vulnerability_Status'"
    }

    $debugMessage = 'Listing endpoints'

    if ($debugFilters.Count -gt 0) {
        $debugMessage = '{0} with {1}' -f $debugMessage, ($debugFilters -join ', ')
    }

    Write-Action1Debug "$debugMessage."

    Invoke-Action1PagedGetRequest -Path $path -Label 'Endpoints' -AddArgs $addArgs
}
