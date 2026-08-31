# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Test-Action1JsonSchema {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Json,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Collections.IDictionary]$ValidationMap,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ObjectType = 'JSON object'
    )

    $objectLabel = [string]$ObjectType

    if ([string]::IsNullOrWhiteSpace($objectLabel)) {
        $objectLabel = 'JSON object'
    }
    else {
        $objectLabel = $objectLabel.Trim()
    }

    if ($null -eq $Json) {
        $message = "$objectLabel cannot be null."
        Write-Error $message -ErrorAction Stop
    }

    if ($null -eq $ValidationMap -or $ValidationMap.Count -eq 0) {
        $message = "Cannot validate $objectLabel because validation map is empty."
        Write-Error $message -ErrorAction Stop
    }

    $propertyNames = @(
        foreach ($entry in $ValidationMap.GetEnumerator()) {
            $propertyName = [string]$entry.Key

            if ([string]::IsNullOrWhiteSpace($propertyName)) {
                $message = (
                    "Cannot validate $objectLabel because validation map " +
                    'contains an empty property name.'
                )
                Write-Error $message -ErrorAction Stop
            }

            $propertyName.Trim()
        }
    )

    if (
        -not (Test-ObjectProperties `
            -InputObject $Json `
            -PropertyNames $propertyNames `
            -ObjectName $objectLabel)
    ) {
        foreach ($propertyName in $propertyNames) {
            if (
                -not (Test-ObjectProperties `
                    -InputObject $Json `
                    -PropertyNames @($propertyName) `
                    -ObjectName $objectLabel)
            ) {
                $message = "$objectLabel is missing required property "
                $message += "'$propertyName'."
                Write-Error $message -ErrorAction Stop
            }
        }
    }

    foreach ($entry in $ValidationMap.GetEnumerator()) {
        if ($null -eq $entry.Value) {
            continue
        }

        $propertyName = ([string]$entry.Key).Trim()
        $actualValue = Get-FirstPropertyValue `
            -InputObject $Json `
            -PropertyName @($propertyName)
        $expectedValue = [string]$entry.Value

        if ($actualValue -cne $expectedValue) {
            $message = "$objectLabel property '$propertyName' has value "
            $message += "'$actualValue'. Expected '$expectedValue'."
            Write-Error $message -ErrorAction Stop
        }
    }

    $true
}
