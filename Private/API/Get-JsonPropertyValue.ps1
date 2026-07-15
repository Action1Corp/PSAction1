# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Get-JsonPropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [AllowNull()]
        [string]$JsonContent,
        [Parameter(Position = 1)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$PropertyName
    )

    if ([string]::IsNullOrWhiteSpace($JsonContent)) {
        return $null
    }

    try {
        $jsonObject = ConvertFrom-Json -InputObject $JsonContent
    }
    catch {
        Write-Action1Debug (
            "Failed to parse JSON property value: $($_.Exception.Message)"
        )
        return $null
    }

    if (-not (Test-ObjectProperties $jsonObject $PropertyName 'JSON response')) {
        return $null
    }

    return $jsonObject.PSObject.Properties[$PropertyName].Value
}
