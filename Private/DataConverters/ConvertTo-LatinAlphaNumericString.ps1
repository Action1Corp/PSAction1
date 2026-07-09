# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md
# https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function ConvertTo-LatinAlphaNumericString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$InputString
    )

    if ([string]::IsNullOrWhiteSpace($InputString)) {
        return ''
    }

    $normalizedValue = $InputString.Normalize([Text.NormalizationForm]::FormD)
    $characters = foreach ($character in $normalizedValue.ToCharArray()) {
        $unicodeCategory = [Globalization.CharUnicodeInfo]::GetUnicodeCategory(
            $character
        )

        if ($unicodeCategory -ne [Globalization.UnicodeCategory]::NonSpacingMark) {
            $character
        }
    }

    $wordMatches = [regex]::Matches((-join $characters), '[A-Za-z0-9]+')

    $stringParts = foreach ($match in $wordMatches) {
        $match.Value
    }

    return ($stringParts -join '')
}
