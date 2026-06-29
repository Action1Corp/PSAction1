# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Get-Action1Region {
    [CmdletBinding()]
    param()

    Write-Action1Debug 'Getting configured Action1 region.'

    if (-not [string]::IsNullOrWhiteSpace($Script:Action1_Region)) {
        return $Script:Action1_Region
    }

    if ([string]::IsNullOrWhiteSpace($Script:Action1_BaseURI)) {
        return
    }

    foreach ($region in $Script:Action1_Hosts.GetEnumerator()) {
        if ($region.Value -eq $Script:Action1_BaseURI) {
            return $region.Key
        }
    }
}
