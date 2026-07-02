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
        [string]$Status,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [ValidateSet('', 'SUCCESS', 'WARNING', 'ERROR', 'UNDEFINED')]
        [string]$OnlineStatus,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [ValidateSet('', 'SUCCESS', 'WARNING', 'ERROR', 'UNDEFINED')]
        [string]$UpdateStatus,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [ValidateSet('', 'SUCCESS', 'WARNING', 'ERROR', 'UNDEFINED')]
        [string]$VulnerabilityStatus
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

    if (-not [string]::IsNullOrWhiteSpace($OnlineStatus)) {
        $encodedOnlineStatus = [System.Uri]::EscapeDataString($OnlineStatus)
        $queryArgument = "online_status=$encodedOnlineStatus"
        $addArgs = Join-QueryString -QueryString $addArgs -Argument $queryArgument
        $debugFilters += "online status '$OnlineStatus'"
    }

    if (-not [string]::IsNullOrWhiteSpace($UpdateStatus)) {
        $encodedUpdateStatus = [System.Uri]::EscapeDataString($UpdateStatus)
        $queryArgument = "update_status=$encodedUpdateStatus"
        $addArgs = Join-QueryString -QueryString $addArgs -Argument $queryArgument
        $debugFilters += "update status '$UpdateStatus'"
    }

    if (-not [string]::IsNullOrWhiteSpace($VulnerabilityStatus)) {
        $encodedVulnStatus = [System.Uri]::EscapeDataString($VulnerabilityStatus)
        $queryArgument = "vulnerability_status=$encodedVulnStatus"
        $addArgs = Join-QueryString -QueryString $addArgs -Argument $queryArgument
        $debugFilters += "vulnerability status '$VulnerabilityStatus'"
    }

    $debugMessage = 'Listing endpoints'

    if ($debugFilters.Count -gt 0) {
        $debugMessage = '{0} with {1}' -f $debugMessage, ($debugFilters -join ', ')
    }

    Write-Action1Debug "$debugMessage."

    Invoke-Action1PagedGetRequest -Path $path -Label 'Endpoints' -AddArgs $addArgs
}
