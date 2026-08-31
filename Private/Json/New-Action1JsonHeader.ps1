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
        [System.Collections.IDictionary]$HeaderTemplate,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Collections.IDictionary]$PropertyValues
    )

    $header = [ordered]@{}
    $templatePropertyNames = @()

    foreach ($entry in $HeaderTemplate.GetEnumerator()) {
        $propertyName = [string]$entry.Key

        if ([string]::IsNullOrWhiteSpace($propertyName)) {
            Write-Error 'JSON header contains an empty property name.' `
                -ErrorAction Stop
        }

        $propertyName = $propertyName.Trim()

        if ($header.Contains($propertyName)) {
            $message = "JSON header template contains duplicate property "
            $message += "'$propertyName'."
            Write-Error $message -ErrorAction Stop
        }

        $header[$propertyName] = $entry.Value
        $templatePropertyNames += $propertyName
    }

    if ($null -eq $PropertyValues) {
        return $header
    }

    $assignedPropertyNames = @{}

    foreach ($entry in $PropertyValues.GetEnumerator()) {
        $propertyName = [string]$entry.Key

        if ([string]::IsNullOrWhiteSpace($propertyName)) {
            Write-Error 'JSON header property values contain an empty property name.' `
                -ErrorAction Stop
        }

        $propertyName = $propertyName.Trim()

        if ($assignedPropertyNames.ContainsKey($propertyName)) {
            $message = "JSON header property values contain duplicate property "
            $message += "'$propertyName'."
            Write-Error $message -ErrorAction Stop
        }

        if ($templatePropertyNames -cnotcontains $propertyName) {
            $message = "JSON header template does not contain property "
            $message += "'$propertyName'."
            Write-Error $message -ErrorAction Stop
        }

        $assignedPropertyNames[$propertyName] = $true
        $header[$propertyName] = $entry.Value
    }

    $header
}
