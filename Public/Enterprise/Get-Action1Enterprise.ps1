# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1Enterprise {
    [CmdletBinding()]
    param()

    $uriPathBuilder = Get-UriMapValue -Key 'G_Enterprise'

    $uri = & $uriPathBuilder
    $path = "$Script:Action1_BaseURI{0}" -f $uri

    Write-Action1Debug 'Getting current enterprise settings.'

    Invoke-Action1ApiRequest `
        -Method GET `
        -Path $path `
        -Label 'Get current enterprise settings'
}
