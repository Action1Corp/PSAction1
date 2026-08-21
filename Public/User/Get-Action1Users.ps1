# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1Users {
    [CmdletBinding()]
    param()

    $uriPathBuilder = Get-UriMapValue -Key 'G_Users'

    $uri = & $uriPathBuilder
    $path = "$Script:Action1_BaseURI{0}" -f $uri

    Write-Action1Debug 'Listing Action1 users.'

    Invoke-Action1PagedGetRequest -Path $path -Label 'Users'
}

