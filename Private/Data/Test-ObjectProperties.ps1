# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Test-ObjectProperties {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$PropertyNames,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ObjectName = 'object'
    )

    $objectLabel = [string]$ObjectName

    if ([string]::IsNullOrWhiteSpace($objectLabel)) {
        $objectLabel = 'object'
    }
    else {
        $objectLabel = $objectLabel.Trim()
    }

    if ($null -eq $InputObject) {
        Write-Action1Debug "Skipping $objectLabel because it is null."
        return $false
    }

    if ($null -eq $PropertyNames -or $PropertyNames.Count -eq 0) {
        Write-Action1Debug (
            "Cannot validate $objectLabel because no property names were supplied."
        )
        return $false
    }

    $availablePropertyNames = @(
        $InputObject.PSObject.Properties | ForEach-Object { $_.Name }
    )

    foreach ($rawPropertyName in $PropertyNames) {
        $propertyName = [string]$rawPropertyName

        if ([string]::IsNullOrWhiteSpace($propertyName)) {
            Write-Action1Debug (
                "Cannot validate $objectLabel because a property name is empty."
            )
            return $false
        }

        if ($availablePropertyNames -notcontains $propertyName) {
            Write-Action1Debug (
                "Skipping $objectLabel because property '$propertyName' is absent."
            )
            return $false
        }
    }

    return $true
}
