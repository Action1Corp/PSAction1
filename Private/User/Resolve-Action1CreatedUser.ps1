# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Resolve-Action1CreatedUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [ValidateScript({
            Test-Guid -Guid $_ -Label 'UserId'
        })]
        [string[]]$UserIds,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            Test-Email -Email $_
        })]
        [string]$Email
    )

    $existingIds = New-Action1SourceMap -SourceIds $UserIds

    $expectedEmail = $Email.Trim()
    for ($attempt = 1; $attempt -le $Script:Action1_UserCreateRecoveryAttempts; $attempt++) {
        $matchedUsers = @{}
        foreach ($user in Get-Action1Users -ErrorAction Stop) {
            $userId = Get-FirstPropertyValue -InputObject $user -PropertyName @('id')
            $userEmail = Get-FirstPropertyValue -InputObject $user -PropertyName @('email')

            if (
                (Test-Guid -Guid $userId) -and
                -not $existingIds.ContainsKey($userId) -and
                $userEmail -ieq $expectedEmail
            ) {
                $matchedUsers[$userId] = $user
            }
        }

        if ($matchedUsers.Count -eq 1) {
            return @($matchedUsers.Values)[0]
        }

        if ($matchedUsers.Count -gt 1) {
            $message = "Multiple new users match '$expectedEmail' after the create request. "
            $message += 'The created user cannot be identified safely.'
            Write-Error $message -ErrorAction Stop
        }

        if ($attempt -lt $Script:Action1_UserCreateRecoveryAttempts) {
            Write-Action1Debug "Waiting for created user '$expectedEmail' to appear."
            Start-Sleep -Seconds $Script:Action1_UserCreateRecoveryDelaySeconds
        }
    }

    $message = "No new user matching '$expectedEmail' appeared after the known HTTP 400 "
    $message += 'create response. The created user could not be recovered.'
    Write-Error $message -ErrorAction Stop
}
