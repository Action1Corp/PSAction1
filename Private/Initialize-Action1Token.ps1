function Initialize-Action1Token {
    [CmdletBinding()]
    param()

    if (
        ($null -ne $Script:Action1_Token) -and
        ($null -ne $Script:Action1_Token.access_token) -and
        ($Script:Action1_Token.expires_at -ge (Get-Date))
    ) {
        Write-Action1Debug "Current token is valid."
        return $true
    }

    Write-Action1Debug "Token not set or expired, fetching new token."

    $token = Request-Action1Token

    if ($null -ne $token) {
        $Script:Action1_Token = $token
        Write-Action1Debug "Token refresh successful."
        return $true
    }

    Write-Error "Token could not be refreshed, check for errors in output."
    return $false
}