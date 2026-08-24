# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1UserRoles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            Test-Guid -Guid $_ -Label 'UserId'
        })]
        [string]$UserId
    )

    $uriPathBuilder = Get-UriMapValue -Key 'G_UserRoles'

    $uri = & $uriPathBuilder $UserId
    $path = "$Script:Action1_BaseURI{0}" -f $uri

    Write-Action1Debug "Listing roles for user '$UserId'."

    Invoke-Action1PagedGetRequest -Path $path -Label "User roles '$UserId'"
}

