# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-FirstPropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$PropertyName
    )

    if ($null -eq $InputObject) {
        return ''
    }

    if ($null -eq $PropertyName -or $PropertyName.Count -eq 0) {
        return ''
    }

    foreach ($rawPropertyName in $PropertyName) {
        $propertyName = [string]$rawPropertyName

        if ([string]::IsNullOrWhiteSpace($propertyName)) {
            continue
        }

        $propertyName = $propertyName.Trim()

        if ($InputObject.PSObject.Properties.Name -contains $propertyName) {
            $value = $InputObject.$propertyName

            if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
                return ([string]$value).Trim()
            }
        }
    }

    return ''
}
