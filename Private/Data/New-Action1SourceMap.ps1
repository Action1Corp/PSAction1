# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function New-Action1SourceMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$MapObject,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$SourceIds,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$IgnoredPropertyNames
    )

    $lookup = @{}
    $ignoredProperties = @{}

    foreach ($propertyName in @($IgnoredPropertyNames)) {
        if ([string]::IsNullOrWhiteSpace($propertyName)) {
            continue
        }

        $ignoredProperties[$propertyName.Trim()] = $true
    }

    foreach ($sourceId in @($SourceIds)) {
        if ([string]::IsNullOrWhiteSpace($sourceId)) {
            continue
        }

        $lookup[$sourceId.Trim()] = $true
    }

    if ($null -eq $MapObject) {
        return $lookup
    }

    foreach ($property in @($MapObject.PSObject.Properties)) {
        if ($null -eq $property) {
            continue
        }

        $propertyName = [string]$property.Name

        if ([string]::IsNullOrWhiteSpace($propertyName)) {
            continue
        }

        $propertyName = $propertyName.Trim()

        if ($ignoredProperties.ContainsKey($propertyName)) {
            continue
        }

        $lookup[$propertyName] = $true
    }

    $lookup
}
