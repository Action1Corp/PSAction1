# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function ConvertTo-Action1JsonHeaderContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Collections.IDictionary]$Header,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) {
                throw 'JSON items property name cannot be empty.'
            }

            $true
        })]
        [string]$ItemsPropertyName = 'items'
    )

    if ($Header.Count -eq 0) {
        Write-Error 'Cannot convert an empty JSON header.' -ErrorAction Stop
    }

    $itemsPropertyNameValue = ([string]$ItemsPropertyName).Trim()
    $headerContent = @('{')
    $foundItemsProperty = $false

    foreach ($entry in $Header.GetEnumerator()) {
        $propertyName = [string]$entry.Key

        if ([string]::IsNullOrWhiteSpace($propertyName)) {
            Write-Error 'JSON header contains an empty property name.' `
                -ErrorAction Stop
        }

        $propertyName = $propertyName.Trim()

        if ($foundItemsProperty) {
            $message = 'Cannot convert JSON header because property '
            $message += "'$propertyName' appears after '$itemsPropertyNameValue'."
            Write-Error $message -ErrorAction Stop
        }

        if ($propertyName -ceq $itemsPropertyNameValue) {
            $headerContent += (
                '  {0}: [' -f (ConvertTo-JsonValue $propertyName)
            )
            $foundItemsProperty = $true
            continue
        }

        $headerContent += (
            '  {0}: {1},' -f
                (ConvertTo-JsonValue $propertyName),
                (ConvertTo-JsonValue $entry.Value)
        )
    }

    if (-not $foundItemsProperty) {
        $message = "JSON header is missing '$itemsPropertyNameValue'."
        Write-Error $message -ErrorAction Stop
    }

    $headerContent
}
