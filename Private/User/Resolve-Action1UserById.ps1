# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Resolve-Action1UserById {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if (-not (Test-Guid $_)) {
                throw 'UserId must be in the standard GUID format.'
            }

            $true
        })]
        [string]$UserId
    )

    Write-Action1Debug "Resolving user by ID '$UserId'."
    $users = @(Get-Action1Users -ErrorAction Stop)

    $matchedUsers = @(
        $users | Where-Object {
            $_.id -ieq $UserId
        }
    )

    if ($matchedUsers.Count -eq 0) {
        Write-Error "User with ID '$UserId' was not found." -ErrorAction Stop
    }

    return $matchedUsers[0]
}

