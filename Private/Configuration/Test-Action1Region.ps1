# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Test-Action1Region {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Region
    )

    if (
        [string]::IsNullOrWhiteSpace($Region) -or
        -not $Script:Action1_Hosts.Contains($Region)
    ) {
        $validRegions = $Script:Action1_Hosts.Keys -join ', '
        throw "Invalid Action1 region '$Region'. Supported regions: $validRegions."
    }

    $true
}
