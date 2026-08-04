# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Get-UtcTimestamp {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) {
                throw 'UTC timestamp template cannot be empty.'
            }

            $true
        })]
        [string]$Template = $Script:Action1_UtcTimestampTemplate
    )

    $utcNow = (Get-Date).ToUniversalTime()
    $culture = [System.Globalization.CultureInfo]::InvariantCulture

    return $utcNow.ToString($Template, $culture)
}
