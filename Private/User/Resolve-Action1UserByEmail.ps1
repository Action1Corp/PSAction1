# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Resolve-Action1UserByEmail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            Test-Email -Email $_
        })]
        [string]$Email
    )

    Write-Action1Debug "Resolving existing user by email '$Email'."
    $matchedUsers = @{}
    foreach ($user in Get-Action1Users -ErrorAction Stop) {
        $userEmail = Get-FirstPropertyValue -InputObject $user -PropertyName @('email')
        if ($userEmail -ine $Email) {
            continue
        }

        $userId = Get-FirstPropertyValue -InputObject $user -PropertyName @('id')
        if (-not (Test-Guid -Guid $userId)) {
            Write-Error "User matching '$Email' does not have a valid GUID ID." `
                -ErrorAction Stop
        }
        $matchedUsers[$userId] = $user
    }

    if ($matchedUsers.Count -eq 0) {
        Write-Error "User with email '$Email' was not found in the users list." `
            -ErrorAction Stop
    }

    if ($matchedUsers.Count -gt 1) {
        Write-Error "Multiple users with email '$Email' were found in the users list." `
            -ErrorAction Stop
    }

    return @($matchedUsers.Values)[0]
}
