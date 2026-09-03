# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function ConvertTo-JsonValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$Depth = $Script:Action1_JsonObjectConversionDepth
    )

    if ($null -eq $Value) {
        return 'null'
    }

    return (
        $Value |
            ConvertTo-Json -Depth $Depth -Compress
    )
}
