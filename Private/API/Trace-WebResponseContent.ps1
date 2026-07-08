# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Trace-WebResponseContent {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [AllowNull()]
        [object]$Response,
        [Parameter(Position = 1)]
        [AllowNull()]
        [object]$ErrorRecord
    )

    $responseContent = $null

    if ($null -ne $Response) {
        if (-not ($Response -is [System.Net.WebResponse])) {
            $responseContent = [string]$Response
        }
        else {
            try {
                $responseStream = $Response.GetResponseStream()

                if ($null -ne $responseStream) {
                    $streamReader = New-Object System.IO.StreamReader($responseStream)

                    try {
                        $responseContent = $streamReader.ReadToEnd()
                    }
                    finally {
                        $streamReader.Dispose()
                    }
                }
            }
            catch {
                $responseContent = $null
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($responseContent) -and $ErrorRecord) {
        if ($ErrorRecord.ErrorDetails) {
            $responseContent = $ErrorRecord.ErrorDetails.Message
        }
    }

    return $responseContent
}
