# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function ConvertFrom-UtcTimestamp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Timestamp,

        [Parameter(Position = 1)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Template = $Script:Action1_UtcTimestampTemplate
    )

    if ([string]::IsNullOrWhiteSpace($Timestamp)) {
        throw 'UTC timestamp cannot be empty.'
    }

    if ([string]::IsNullOrWhiteSpace($Template)) {
        throw 'UTC timestamp template cannot be empty.'
    }

    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
        [System.Globalization.DateTimeStyles]::AdjustToUniversal

    return [datetime]::ParseExact($Timestamp.Trim(), $Template, $culture, $styles)
}
