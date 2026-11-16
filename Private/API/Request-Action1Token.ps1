# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Request-Action1Token {
    [CmdletBinding()]
    param()

    if (Initialize-Action1Region) {
        if (
            $Script:Action1_APIKey -isnot [System.Security.SecureString] -or
            $Script:Action1_APIKey.Length -eq 0 -or
            $Script:Action1_Secret -isnot [System.Security.SecureString] -or
            $Script:Action1_Secret.Length -eq 0
        ) {
            if ($Script:Action1_Interactive) {
                Set-Action1Credentials 
            }
            else { 
                Write-Error "Authentication details are not set, call Set-Action1Credentials prior to making any calls to the API."
                exit
            } 
        }
        try {
            $tokenRequestErrors = @()
            $token = Invoke-Action1ApiRequest `
                -Method POST `
                -Path "$Script:Action1_BaseURI/oauth2/token" `
                -Label 'Request OAuth2 token' `
                -Body @{
                    # Expose plaintext only for the OAuth request, not module state.
                    # NetworkCredential supports SecureString in PowerShell 5.1.
                    client_id     = (New-Object System.Net.NetworkCredential `
                        -ArgumentList 'Action1', $Script:Action1_APIKey `
                        -ErrorAction Stop).Password
                    client_secret = (New-Object System.Net.NetworkCredential `
                        -ArgumentList 'Action1', $Script:Action1_Secret `
                        -ErrorAction Stop).Password
                } `
                -SkipAuthenticationCheck `
                -SensitiveData `
                -ErrorVariable tokenRequestErrors
            if ($null -eq $token) {
                $hasTokenRequestError = $false

                foreach ($tokenRequestError in @($tokenRequestErrors)) {
                    if (
                        $tokenRequestError.FullyQualifiedErrorId -match
                        '^Action1ApiRequestHttp(400|401),'
                    ) {
                        $hasTokenRequestError = $true
                        break
                    }
                }

                if (-not $hasTokenRequestError) {
                    Write-Error "Error fetching auth token: token request failed."
                }

                return $null
            }

            $token | Add-Member -MemberType NoteProperty -Name "expires_at" -Value $(Get-Date).AddSeconds(([int]$token.expires_in - 5)) #Expire token 5 seconds early to avoid race condition timeouts.
            return $token
        }
        catch [System.Net.WebException] {
            Write-Error 'Error fetching auth token: authentication request failed.'
            return $null
        }     
    }
}
