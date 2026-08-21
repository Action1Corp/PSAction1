# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1User {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if (-not (Test-Guid $_)) {
                throw 'UserId must be in the standard GUID format.'
            }

            $true
        })]
        [string]$UserId
    )

    $uriPathBuilder = Get-UriMapValue -Key 'G_User'

    $uri = & $uriPathBuilder $UserId
    $path = "$Script:Action1_BaseURI{0}" -f $uri

    Write-Action1Debug "Getting user '$UserId'."

    Invoke-Action1ApiRequest -Method GET -Path $path -Label "User '$UserId'"
}
