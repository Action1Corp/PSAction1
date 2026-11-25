# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Test-Action1AutomationAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [object]$Action
    )

    if (
        $Action -isnot [System.Collections.IDictionary] -and
        $Action -isnot [PSCustomObject]
    ) {
        throw 'Each action must be a dictionary or PSCustomObject.'
    }
    $actionObject = [pscustomobject]$Action
    foreach ($propertyName in @('name', 'template_id')) {
        if (
            $actionObject.$propertyName -isnot [string] -or
            [string]::IsNullOrWhiteSpace($actionObject.$propertyName)
        ) {
            throw "Each action must have a nonempty $propertyName string."
        }
    }
    if ($actionObject.PSObject.Properties.Name -contains 'id') {
        if ($actionObject.id -isnot [string] -or [string]::IsNullOrWhiteSpace($actionObject.id)) {
            throw 'An action ID, when supplied, must be a nonempty string.'
        }
    }
    if (
        $actionObject.params -isnot [System.Collections.IDictionary] -and
        $actionObject.params -isnot [PSCustomObject]
    ) {
        throw 'Each action must have a params object.'
    }
    $parameterObject = [pscustomobject]$actionObject.params
    if ($parameterObject.PSObject.Properties.Name -contains 'filters') {
        if ($parameterObject.filters -isnot [array]) {
            throw 'Action filters must be an array.'
        }
        foreach ($filter in $parameterObject.filters) {
            if (
                $filter -isnot [System.Collections.IDictionary] -and
                $filter -isnot [PSCustomObject]
            ) {
                throw 'Each filter must be an object.'
            }
            $filterObject = [pscustomobject]$filter
            if ($filterObject.name -isnot [string] -or $filterObject.operator -isnot [string]) {
                throw 'Each filter must have name and operator strings.'
            }
            if ($filterObject.values -isnot [array]) {
                throw 'Filter values must be an array.'
            }
            foreach ($value in $filterObject.values) {
                if ($value -isnot [string]) {
                    throw 'Filter values must be strings.'
                }
            }
            $null = New-Action1AutomationActionFilter -Name $filterObject.name `
                -Values $filterObject.values -Operator $filterObject.operator
        }
    }
    return $true
}
