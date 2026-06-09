function Request-Action1Token {
    [CmdletBinding()]
    param()

    if (Initialize-Action1Region) {
        if ([string]::IsNullOrEmpty($Script:Action1_APIKey) -or [string]::IsNullOrEmpty($Script:Action1_Secret)) {
            if ($Script:Action1_Interactive) {
                Set-Action1Credentials 
            }
            else { 
                Write-Error "Authentication details are not set, call Set-Action1Credentials prior to making any calls to the API."
                exit
            } 
        }
        try {
            $Token = Invoke-Action1ApiRequest `
                -Method POST `
                -Path "$Script:Action1_BaseURI/oauth2/token" `
                -Label 'Request OAuth2 token' `
                -Body @{
                    client_id     = $Script:Action1_APIKey
                    client_secret = $Script:Action1_Secret
                } `
                -SkipAuthenticationCheck
            $Token | Add-Member -MemberType NoteProperty -Name "expires_at" -Value $(Get-Date).AddSeconds(([int]$Token.expires_in - 5)) #Expire token 5 seconds early to avoid race condition timeouts.
            return $Token
        }
        catch [System.Net.WebException] {
            Write-Error "Error fetching auth token: $($_)."
            Write-Error $Token
            return $null
        }     
    }
}