# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function ConvertTo-Action1JsonPropertyContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) {
                throw 'JSON property name cannot be empty.'
            }

            $true
        })]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value
    )

    $propertyName = $Name.Trim()
    $jsonValue = ConvertTo-Json `
        -InputObject $Value `
        -Depth $Script:Action1_JsonObjectConversionDepth
    $jsonValueLines = @($jsonValue -split "`r?`n")
    $propertyNameValue = ConvertTo-JsonValue -Value $propertyName
    $content = @()

    if ($jsonValueLines.Count -eq 0) {
        return @('  {0}: null' -f $propertyNameValue)
    }

    $content += ('  {0}: {1}' -f $propertyNameValue, $jsonValueLines[0])

    for ($i = 1; $i -lt $jsonValueLines.Count; $i++) {
        $content += ('  {0}' -f $jsonValueLines[$i])
    }

    $content
}
