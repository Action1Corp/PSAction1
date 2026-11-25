# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function ConvertFrom-Action1AutomationDefinition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [ValidateSet('3.0', '4.0')]
        [string]$ApiVersion
    )

    if (
        $InputObject -isnot [System.Collections.IDictionary] -and
        $InputObject -isnot [PSCustomObject]
    ) {
        throw 'The existing automation must be a dictionary or PSCustomObject, not JSON text.'
    }
    $source = [pscustomobject]$InputObject
    if (
        $source.PSObject.Properties.Name -contains 'items' -or
        ($source.type -and $source.type -notin @(
            'AutomationInstance', 'AutomationSchedule', 'AutomationScheduleConfiguration'
        ))
    ) {
        throw 'Supply one automation instance, schedule, or definition, not a result page.'
    }

    $configuration = $source
    $nested = $source.PSObject.Properties.Name -contains 'configuration'
    if ($nested) {
        if ($ApiVersion -eq '3.0') {
            throw 'API 3.0 requires an existing flat definition.'
        }
        if (
            $source.configuration -isnot [System.Collections.IDictionary] -and
            $source.configuration -isnot [PSCustomObject]
        ) {
            throw 'The existing configuration must be a dictionary or PSCustomObject.'
        }
        $configuration = [pscustomobject]$source.configuration
    }
    elseif ($ApiVersion -eq '4.0' -and $source.type -eq 'AutomationSchedule') {
        throw 'API 4.0 requires a nested configuration for an existing schedule.'
    }

    # Retain configuration fields, including IDs and extensions. Exclude known
    # response metadata and signatures without deciding between POST and PATCH.
    $excludedProperties = @(
        'configuration', 'endpoints', 'signatures', 'self', 'last_run', 'next_run',
        'status', 'percent_completed', 'endpoint_results', 'end_time', 'schedule',
        'total_items', 'limit', 'from', 'next_page', 'prev_page'
    )
    $config = [ordered]@{}
    foreach ($property in $configuration.PSObject.Properties) {
        if ($property.Name -in $excludedProperties) {
            continue
        }
        if (
            $property.Name -eq 'type' -and -not $nested -and
            $source.type -ne 'AutomationScheduleConfiguration'
        ) {
            continue
        }
        $config[$property.Name] = $property.Value
    }
    if ($ApiVersion -eq '4.0' -and -not $config.Contains('type')) {
        $config['type'] = 'AutomationScheduleConfiguration'
    }

    $targets = $null
    if ($source.PSObject.Properties.Name -contains 'endpoints') {
        $targets = $source.endpoints
    }
    [pscustomobject]@{
        Configuration = [pscustomobject]$config
        Endpoints     = $targets
    }
}
