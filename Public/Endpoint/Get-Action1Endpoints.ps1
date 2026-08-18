# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1Endpoints {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('Connected', 'Disconnected', 'Pending Uninstall', 'All')]
        [string]$Status = 'All',
        [Parameter(Mandatory = $false)]
        [ValidateSet('Yes', 'No', 'All')]
        [string]$RebootRequired = 'All',
        [Parameter(Mandatory = $false)]
        [ValidateSet('Windows 11', 'Windows 10', 'Windows Server', 'macOS', 'linux', 'All')]
        [string]$OS = 'All'
    )

    if (Initialize-Action1DefaultOrg) {
        $orgId = Get-Action1DefaultOrgId
    }

    $uriPathBuilder = Get-UriMapValue -Key 'G_Endpoints'

    $uri = & $uriPathBuilder $orgId
    $path = "$Script:Action1_BaseURI{0}" -f $uri
    $addArgs = $null
    $debugFilters = @()

    if ($Status -ne 'All') {
        $encodedStatus = [System.Uri]::EscapeDataString($Status)
        $queryArgument = "status=$encodedStatus"
        $addArgs = Join-QueryString -QueryString $addArgs -Argument $queryArgument
        $debugFilters += "status '$Status'"
    }

    if ($RebootRequired -ne 'All') {
        $encodedRebootRequired = [System.Uri]::EscapeDataString($RebootRequired)
        $queryArgument = "reboot_required=$encodedRebootRequired"
        $addArgs = Join-QueryString -QueryString $addArgs -Argument $queryArgument
        $debugFilters += "reboot required '$RebootRequired'"
    }

    if ($OS -ne 'All') {
        $encodedOS = [System.Uri]::EscapeDataString($OS)
        $queryArgument = "OS=$encodedOS"
        $addArgs = Join-QueryString -QueryString $addArgs -Argument $queryArgument
        $debugFilters += "OS '$OS'"
    }

    $debugMessage = 'Listing endpoints'

    if ($debugFilters.Count -gt 0) {
        $debugMessage = '{0} with {1}' -f $debugMessage, ($debugFilters -join ', ')
    }

    Write-Action1Debug "$debugMessage."

    Invoke-Action1PagedGetRequest -Path $path -Label 'Endpoints' -AddArgs $addArgs
}
