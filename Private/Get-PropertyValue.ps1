# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-PropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($CurrentName in $Name) {
            if ($InputObject.Contains($CurrentName) -and $null -ne $InputObject[$CurrentName]) {
                return $InputObject[$CurrentName]
            }
        }
    }

    foreach ($CurrentName in $Name) {
        $Property = $InputObject.PSObject.Properties[$CurrentName]
        if ($null -ne $Property -and $null -ne $Property.Value) {
            return $Property.Value
        }
    }

    return $null
}