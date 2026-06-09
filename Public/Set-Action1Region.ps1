# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Set-Action1Region {
    param (
        [Parameter(Mandatory)]
        [ValidateSet('NorthAmerica', 'Europe', 'Australia')]
        [String]$Region
    )
    $Script:Action1_BaseURI = $Script:Action1_Hosts[$Region]
}