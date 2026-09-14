# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Test-Action1UserCreateError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$RequiredText = $Script:Action1_UserCreateRecoveryErrorText
    )

    if ($null -eq $ErrorRecord) {
        return $false
    }

    $errorText = $ErrorRecord.Exception.Message
    if ($null -ne $ErrorRecord.ErrorDetails) {
        $errorText += [Environment]::NewLine + $ErrorRecord.ErrorDetails.Message
    }

    $statusCode = 0
    $responseProperty = $ErrorRecord.Exception.PSObject.Properties['Response']
    if ($null -ne $responseProperty -and $null -ne $responseProperty.Value) {
        $statusProperty = $responseProperty.Value.PSObject.Properties['StatusCode']
        if ($null -ne $statusProperty -and $null -ne $statusProperty.Value) {
            $statusCode = [int]$statusProperty.Value
        }
    }

    if ($statusCode -eq 0) {
        if ($ErrorRecord.FullyQualifiedErrorId -match '^Action1ApiRequestHttp(\d{3})(?:,|$)') {
            $statusCode = [int]$Matches[1]
        }
        elseif ($errorText -match '\bHTTP status code\s+(\d{3})\b') {
            $statusCode = [int]$Matches[1]
        }
        elseif ($errorText -match '"status"\s*:\s*(\d{3})\b') {
            $statusCode = [int]$Matches[1]
        }
    }

    if ($statusCode -ne 400) {
        return $false
    }

    if ($null -eq $RequiredText -or $RequiredText.Count -eq 0) {
        return $false
    }

    foreach ($text in $RequiredText) {
        if ([string]::IsNullOrWhiteSpace($text)) {
            return $false
        }
        if ($errorText.IndexOf($text, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
            return $false
        }
    }

    $true
}
