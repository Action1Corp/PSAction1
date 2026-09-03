# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function ConvertTo-Action1JsonObjectContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $false)]
        [switch]$OmitClosingBrace
    )

    $jsonContent = ConvertTo-Json `
        -InputObject $InputObject `
        -Depth $Script:Action1_JsonObjectConversionDepth
    $jsonLines = @($jsonContent -split "`r?`n")

    if (-not $OmitClosingBrace.IsPresent) {
        return $jsonLines
    }

    if ($jsonLines.Count -eq 0) {
        Write-Error 'Cannot omit the closing brace from empty JSON content.' `
            -ErrorAction Stop
    }

    $lastJsonLineIndex = $jsonLines.Count - 1

    while (
        $lastJsonLineIndex -ge 0 -and
        [string]::IsNullOrWhiteSpace($jsonLines[$lastJsonLineIndex])
    ) {
        $lastJsonLineIndex--
    }

    if ($lastJsonLineIndex -lt 0 -or $jsonLines[$lastJsonLineIndex].Trim() -cne '}') {
        Write-Error 'JSON content does not end with an object closing brace.' `
            -ErrorAction Stop
    }

    if ($lastJsonLineIndex -eq 0) {
        return @()
    }

    $jsonLines[0..($lastJsonLineIndex - 1)]
}
