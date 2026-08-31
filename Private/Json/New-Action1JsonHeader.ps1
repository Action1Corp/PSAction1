# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function New-Action1JsonHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) {
                throw 'JSON schema cannot be empty.'
            }

            $true
        })]
        [string]$Schema,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) {
                throw 'JSON object type cannot be empty.'
            }

            $true
        })]
        [string]$Type,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Collections.IDictionary]$PropertyValues
    )

    if (
        $null -eq $Script:Action1_DefaultJsonHeader -or
        $Script:Action1_DefaultJsonHeader.Count -eq 0
    ) {
        Write-Error 'Default JSON header configuration is empty.' `
            -ErrorAction Stop
    }

    $header = [ordered]@{}

    foreach ($entry in $Script:Action1_DefaultJsonHeader.GetEnumerator()) {
        $propertyName = [string]$entry.Key

        if ([string]::IsNullOrWhiteSpace($propertyName)) {
            Write-Error 'Default JSON header contains an empty property name.' `
                -ErrorAction Stop
        }

        $header[$propertyName.Trim()] = $entry.Value
    }

    $header['schema'] = ([string]$Schema).Trim()
    $header['datetime'] = Get-UtcTimestamp
    $header['type'] = ([string]$Type).Trim()

    if ($null -eq $PropertyValues) {
        return $header
    }

    foreach ($entry in $PropertyValues.GetEnumerator()) {
        $propertyName = [string]$entry.Key

        if ([string]::IsNullOrWhiteSpace($propertyName)) {
            Write-Error 'JSON header property values contain an empty property name.' `
                -ErrorAction Stop
        }

        $propertyName = $propertyName.Trim()

        if ($header.Contains($propertyName)) {
            $header[$propertyName] = $entry.Value
            continue
        }

        $insertIndex = [array]::IndexOf(@($header.Keys), 'type')

        if ($insertIndex -lt 0) {
            $insertIndex = [array]::IndexOf(@($header.Keys), 'items')
        }

        if ($insertIndex -lt 0) {
            $header[$propertyName] = $entry.Value
        }
        else {
            $header.Insert($insertIndex, $propertyName, $entry.Value)
        }
    }

    $header
}
