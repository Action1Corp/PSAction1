---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# New-Action1AutomationActionFilter

## SYNOPSIS

Builds an automation action filter locally.

## SYNTAX

```powershell
New-Action1AutomationActionFilter -Name <String> -Values <String[]> -Operator <String> [<CommonParameters>]
```

## DESCRIPTION

Creates an object with `name`, `values`, and `operator` for an action's
`params.filters` array. No API request is made. Values remain an array even
when there is only one value. The operator is normalized to lowercase.

Separate update filters combine with AND; included values within one filter
combine with OR. The include/exclude operator controls whether matching values
are selected or excluded. Filter names and values are not restricted to a
hard-coded catalogue; API support depends on the action and API version.

Use the returned object inside the Parameters dictionary of
**New-Action1AutomationAction**, then place that action in a run-now or schedule
definition. Filters select action content; they do not select endpoint targets.
The definition is submitted with **Start-Action1Automation** or
**New-Action1AutomationSchedule**, and updated schedules use
**Update-Action1AutomationSchedule**.

There is no existing-object parameter. Reconstruct a stored filter by explicitly
passing its name, values, and operator. Enclosing definition builders can also
inherit the existing actions and filters without reconstructing them.

The examples use API 4.0 and the configured default test organization.
The endpoint and Automation getters contact Action1 and require an authenticated
session; the builders themselves only construct objects locally. Configure
**Set-Action1Sign** before submitting an API 4.0 definition. See the related
submission command for the complete create/read/cleanup flow.

## EXAMPLES

### Example 1: Build a filter, action, and new Automation definition

```powershell
$filter = New-Action1AutomationActionFilter -Name update_types `
    -Values 'Security Updates' -Operator include
$action = New-Action1AutomationAction -Name 'Security updates' `
    -TemplateId deploy_update -Parameters @{
        scope = 'MatchingFilters'
        filters = @($filter)
        reboot_options = @{ auto_reboot = 'no' }
    }

$endpoints = @(Get-Action1Endpoints -Status Connected -ErrorAction Stop)
if ($endpoints.Count -eq 0) { throw 'No connected test endpoint was returned.' }
$target = New-Action1AutomationTarget -Id $endpoints[0].id -Type Endpoint

$runName = 'Documentation run ' + [guid]::NewGuid().ToString('N')
$definition = New-Action1AutomationDefinition -Name $runName `
    -Actions @($action) -Endpoints @($target) -RetryMinutes 10 `
    -ApiVersion '4.0' -OrganizationId (Get-Action1DefaultOrgId) `
    -StartTime ([DateTimeOffset]::UtcNow)
```

The singleton filter value is kept as an array and the filter is wrapped in the
action parameter `filters` array. Targets are supplied separately. This only builds
the unsigned definition; **Start-Action1Automation** submits it and creates a run.

### Example 2: Reconstruct a filter from an existing action

```powershell
$schedules = @(Get-Action1AutomationSchedules -ErrorAction Stop)
if ($schedules.Count -eq 0) { throw 'No source schedule was returned.' }
$source = Get-Action1AutomationSchedule `
    -AutomationInstanceId $schedules[0].id -ErrorAction Stop
$sourceActions = @($source.configuration.actions | Where-Object { $null -ne $_ })
if ($sourceActions.Count -eq 0) { throw 'The source schedule has no actions.' }
$sourceAction = $sourceActions[0]
$sourceFilters = @($sourceAction.params.filters | Where-Object { $null -ne $_ })
if ($sourceFilters.Count -eq 0) { throw 'The source action has no filters.' }
$sourceFilter = $sourceFilters[0]
$filter = New-Action1AutomationActionFilter -Name $sourceFilter.name `
    -Values @($sourceFilter.values) -Operator $sourceFilter.operator
$parameters = @{}
foreach ($property in $sourceAction.params.PSObject.Properties) {
    $parameters[$property.Name] = $property.Value
}
$parameters.filters = @($filter)
$rebuiltAction = New-Action1AutomationAction -Name $sourceAction.name `
    -TemplateId $sourceAction.template_id -Parameters $parameters
$definition = New-Action1AutomationScheduleDefinition -ExistingSchedule $source `
    -Actions @($rebuiltAction) -Settings DISABLED -ApiVersion '4.0'
```

There is no ExistingFilter parameter. This example passes the retrieved filter
fields explicitly and replaces the first action with a rebuilt action containing
only that filter. It copies the parameter properties into a new dictionary before
replacing filters; it does not edit the retrieved parameter object in place.

### Example 3: Build an explicit exclusion filter

```powershell
$excludedSources = New-Action1AutomationActionFilter -Name update_sources `
    -Values Applications -Operator exclude
```

Builds another local filter object. Add it to the action filters array only when
the selected action and API version support that key and value. Structural
validation does not check the server catalogue or execute an Automation.

## PARAMETERS

### -Name

The API filter key. Known captured keys are update_types, update_sources, and update_security_severities. Must be nonempty and non-whitespace.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Values

One or more nonempty, non-whitespace filter values. Null entries are rejected.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Operator

The filter operation. Accepted values: include, exclude.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe input to this command.

## OUTPUTS

### System.Management.Automation.PSCustomObject

Returns one PSCustomObject containing `name`, `values` as an array, and `operator`.

## NOTES

This command validates filter structure. It does not discover filter keys or
validate values against the server. Select keys and values supported by the
chosen action and API version.

## RELATED LINKS

[New-Action1AutomationAction](New-Action1AutomationAction.md)
[New-Action1AutomationDefinition](New-Action1AutomationDefinition.md)
[New-Action1AutomationScheduleDefinition](New-Action1AutomationScheduleDefinition.md)
[Start-Action1Automation](Start-Action1Automation.md)
[New-Action1AutomationSchedule](New-Action1AutomationSchedule.md)
[Get-Action1Endpoints](../endpoint/Get-Action1Endpoints.md)
[Get-Action1EndpointGroups](../endpointgroup/Get-Action1EndpointGroups.md)
