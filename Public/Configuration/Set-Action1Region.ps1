# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Set-Action1Region {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Action1Region -Region $_ })]
        [String]$Region
    )

    switch ($Region) {
        'NA-2' {
            Write-Warning "'NA-2' is a temporary region name. Please use 'NA2' instead."
        }
        'NorthAmerica-2' {
            Write-Warning "'NorthAmerica-2' is a temporary region name. Please use 'NorthAmerica2' instead."
        }
    }

    $Script:Action1_BaseURI = $Script:Action1_Hosts[$Region]
    $Script:Action1_Region = $Region
    Write-Action1Debug "Action1 region set to '$Region'."
}
