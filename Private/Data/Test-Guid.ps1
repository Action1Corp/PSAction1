# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Test-Guid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Guid,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Label
    )

    $isValid = $false

    if (-not [string]::IsNullOrWhiteSpace($Guid)) {
        $parsedGuid = [guid]::Empty
        $isValid = [guid]::TryParseExact($Guid.Trim(), 'D', [ref]$parsedGuid)
    }

    if (
        -not $isValid -and
        $PSBoundParameters.ContainsKey('Label') -and
        -not [string]::IsNullOrWhiteSpace($Label)
    ) {
        throw "$Label must be in the standard GUID format."
    }

    return $isValid
}
