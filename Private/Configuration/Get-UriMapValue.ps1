# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-UriMapValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Key
    )

    $keyName = [string]$Key

    if ([string]::IsNullOrWhiteSpace($keyName)) {
        $message = 'Action1 URI map key name is not defined.'
        Write-Action1Debug $message
        throw $message
    }

    $keyName = $keyName.Trim()

    if ($null -eq $Script:Action1_UriMap) {
        $message = 'Action1 URI map is not defined.'
        Write-Action1Debug $message
        throw $message
    }

    if (-not ($Script:Action1_UriMap -is [System.Collections.IDictionary])) {
        $message = 'Action1 URI map is not a dictionary.'
        Write-Action1Debug $message
        throw $message
    }

    if (-not $Script:Action1_UriMap.ContainsKey($keyName)) {
        $message = "Action1 URI map key '$keyName' is not defined."
        Write-Action1Debug $message
        throw $message
    }

    return $Script:Action1_UriMap[$keyName]
}
