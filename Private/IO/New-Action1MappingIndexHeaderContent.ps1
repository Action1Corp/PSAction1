# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function New-Action1MappingIndexHeaderContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Collections.IDictionary]$HeaderValues
    )

    $header = New-Action1JsonHeader `
        -HeaderTemplate $Script:Action1_MappingIndexTextHeader `
        -PropertyValues $HeaderValues

    $content = @()

    foreach ($entry in $header.GetEnumerator()) {
        $propertyName = [string]$entry.Key

        if ([string]::IsNullOrWhiteSpace($propertyName)) {
            Write-Error 'Mapping index header contains an empty property name.' `
                -ErrorAction Stop
        }

        $content += ('# {0}={1}' -f $propertyName.Trim(), $entry.Value)
    }

    $content += $Script:Action1_MappingIndexTextHeaderEnd
    $content
}
