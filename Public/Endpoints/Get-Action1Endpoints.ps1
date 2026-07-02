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
        $Org_ID = Get-Action1DefaultOrgId
    }

    if (-not $Script:Action1_UriMap.ContainsKey('G_Endpoints')) {
        throw "Action1 URI map key 'G_Endpoints' is not defined."
    }

    $Endpoint = & $Script:Action1_UriMap['G_Endpoints'] $Org_ID
    $Path = "$Script:Action1_BaseURI{0}" -f $Endpoint
    $AddArgs = $null
    $DebugFilters = @()

    if (-not [string]::IsNullOrWhiteSpace($Status)) {
        $EncodedStatus = [System.Uri]::EscapeDataString($Status)
        $QueryArgument = "status=$EncodedStatus"
        $AddArgs = Join-QueryString -QueryString $AddArgs -Argument $QueryArgument
        $DebugFilters += "status '$Status'"
    }

    if (-not [string]::IsNullOrWhiteSpace($Online_Status)) {
        $EncodedOnlineStatus = [System.Uri]::EscapeDataString($Online_Status)
        $QueryArgument = "online_status=$EncodedOnlineStatus"
        $AddArgs = Join-QueryString -QueryString $AddArgs -Argument $QueryArgument
        $DebugFilters += "online status '$Online_Status'"
    }

    if (-not [string]::IsNullOrWhiteSpace($Updater_Status)) {
        $EncodedUpdaterStatus = [System.Uri]::EscapeDataString($Updater_Status)
        $QueryArgument = "updater_status=$EncodedUpdaterStatus"
        $AddArgs = Join-QueryString -QueryString $AddArgs -Argument $QueryArgument
        $DebugFilters += "updater status '$Updater_Status'"
    }

    if (-not [string]::IsNullOrWhiteSpace($Vulnerability_Status)) {
        $EncodedVulnStatus = [System.Uri]::EscapeDataString($Vulnerability_Status)
        $QueryArgument = "vulnerability_status=$EncodedVulnStatus"
        $AddArgs = Join-QueryString -QueryString $AddArgs -Argument $QueryArgument
        $DebugFilters += "vulnerability status '$Vulnerability_Status'"
    }

    $DebugMessage = 'Listing endpoints'

    if ($DebugFilters.Count -gt 0) {
        $DebugMessage = '{0} with {1}' -f $DebugMessage, ($DebugFilters -join ', ')
    }

    Write-Action1Debug "$DebugMessage."

    Invoke-Action1PagedGetRequest -Path $Path -Label 'Endpoints' -AddArgs $AddArgs
}
