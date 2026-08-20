# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Remove-Action1User {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if (-not (Test-Guid $_)) {
                throw 'UserId must be in the standard GUID format.'
            }

            $true
        })]
        [string]$UserId,

        [switch]$Force
    )

    $uriPathBuilder = Get-UriMapValue -Key 'D_User'

    $uri = & $uriPathBuilder $UserId
    $path = "$Script:Action1_BaseURI{0}" -f $uri
    $target = "User '$UserId'"

    if ($Force) {
        $ConfirmPreference = 'None'
    }

    if (-not $PSCmdlet.ShouldProcess($target, 'Delete Action1 user')) {
        Write-Action1Debug "Skipped deleting user '$UserId'."

        [pscustomobject]@{
            UserId   = $UserId
            Status   = 'Skipped'
            Response = $null
        }
        return
    }

    Write-Action1Debug "Deleting user '$UserId'."

    $response = Invoke-Action1ApiRequest `
        -Method DELETE `
        -Path $path `
        -Label "Delete user '$UserId'" `
        -RawResponse

    if ($null -eq $response) {
        Write-Error "Failed to delete user '$UserId'."

        [pscustomobject]@{
            UserId   = $UserId
            Status   = 'Failed'
            Response = $null
        }
        return
    }

    Write-Action1Debug "Deleted user '$UserId'."

    [pscustomobject]@{
        UserId   = $UserId
        Status   = 'Removed'
        Response = $response
    }
}
