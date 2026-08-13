# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Invoke-Action1ApiRequest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
        [string]$Method,
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Label,
        [hashtable]$Headers,
        [object]$Body,
        [switch]$RawBody,
        [string]$AddArgs,
        [switch]$RawResponse,
        [switch]$SkipAuthenticationCheck
    )

    if ($AddArgs) {
        $Path += "?{0}" -f $AddArgs
    }

    $requestHeaders = @{}

    if (-not $SkipAuthenticationCheck) {
        if (-not (Initialize-Action1Token)) {
            Write-Action1Debug "No authentication token. Aborting $Method request to $Path."
            return $null
        }

        if ([string]::IsNullOrEmpty($Script:Action1_Token.access_token)) {
            Write-Action1Debug "No authentication token. Aborting $Method request to $Path."
            return $null
        }

        $requestHeaders.Authorization = "Bearer $($Script:Action1_Token.access_token)"
    }

    $requestHeaders['Content-Type'] = 'application/json; charset=utf-8'

    if ($Headers) {
        foreach ($key in @($Headers.Keys)) {
            $requestHeaders[$key] = $Headers[$key]
        }
    }

    $requestBody = $null

    if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
        if ($RawBody) {
            $requestBody = $Body
            Write-Action1Debug "Raw request body supplied. Type: $($requestBody.GetType().FullName)"
        }
        else {
            $requestBody = ConvertTo-Json `
                -InputObject $Body `
                -Depth $Script:Action1_JsonObjectConversionDepth
            Write-Action1Debug "JSON Data to be sent:`n$requestBody"  
        }
    }

    $invokeWebRequestParams = @{
        Uri             = $Path
        Method          = $Method
        UseBasicParsing = $true
        Headers         = $requestHeaders
        ErrorAction     = 'Stop'
    }

    if ($null -ne $requestBody) {
        $invokeWebRequestParams.Body = $requestBody
    }

    $retry429Count = 0
    $retry429BaseTimeoutSeconds = $Script:Action1_429RetryBaseTimeoutSeconds

    while ($true) {
        try {
            if($Script:Action1_DebugEnabled){$webRequestSW = [System.Diagnostics.Stopwatch]::StartNew()}

            $response = Invoke-WebRequest @invokeWebRequestParams

            if($Script:Action1_DebugEnabled){
                $webRequestSW.Stop()
                Write-Action1Debug ("{2} request to {0} took {1}ms. RawResponse flag is {3}" -f $Path, $($webRequestSW.ElapsedMilliseconds), $Method, $RawResponse)
            }

            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
                Write-Action1Debug ("Success response code {0} for {1} request to {2}" -f $($response.StatusCode), $Method, $Path)
                if ($RawResponse) {
                    return $response.Content
                }

                if ([string]::IsNullOrWhiteSpace($response.Content)) {
                    return $null
                }

                return ConvertFrom-Json -InputObject $response.Content
            }

            Write-Action1Debug "Error processing $($Label): HTTP status code $($response.StatusCode)."
            return $null
        }
        catch {
            $statusCode = $null
            $exceptionResponse = $_.Exception.Response

            if ($exceptionResponse) {
                $statusCode = [int]$exceptionResponse.StatusCode
            }

            $responseContentParams = @{
                    Response    = $exceptionResponse
                    ErrorRecord = $_
            }
            $responseContent = Trace-WebResponseContent @responseContentParams
            $errorDetails = Get-JsonPropertyValue `
                -JsonContent $responseContent `
                -PropertyName 'details'
            if ([string]::IsNullOrWhiteSpace($responseContent)) {
                $responseContent = '<empty response content>'
            }

            Write-Action1Debug (
                "Failed response code {0} for {1} request to {2}. Response: {3}" -f
                $statusCode, $Method, $Path, $responseContent
            )

            if ($statusCode -eq 429) {
                $retryTimeout = $null
                if (Test-ObjectProperties $errorDetails 'retry_after' 'error details') {
                    $retryAfter = 0
                    $parsedRetryAfter = [int]::TryParse(
                        [string]$errorDetails.retry_after,
                        [ref]$retryAfter
                    )

                    if ($parsedRetryAfter -and $retryAfter -gt 0) {
                        $retryTimeout = $retryAfter
                    }
                }

                if ($null -eq $retryTimeout) {
                    $retryTimeout = [int](
                        [Math]::Pow(2, $retry429Count) * $retry429BaseTimeoutSeconds
                    )
                }

                $retry429Count++

                Write-Action1Debug (
                    "429 received for {0}. Retry #{1}. Sleeping {2} seconds." -f
                    $Label, $retry429Count, $retryTimeout
                )

                Start-Sleep -Seconds $retryTimeout
                continue
            }

            Write-Action1Debug "Error processing $($Label): $($_.Exception.Message)"
            return $null
        }
    }
}
