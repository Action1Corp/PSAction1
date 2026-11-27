---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# New-Action1AutomationAction

## SYNOPSIS

Builds an automation action locally from a template and parameter object.

## SYNTAX

```powershell
New-Action1AutomationAction -Name <String> -TemplateId <String> -Parameters <Object> [-ActionId <String>] [<CommonParameters>]
```

## DESCRIPTION

Creates one action containing `name`, `template_id`, `params`, and `id`.
The action can be reused with API 3.0 or API 4.0 definition builders.
No API request is made. Parameter properties populate the local action template
directly. Nested parameter objects are reused, so later edits to those objects
can affect the caller's original objects.

Local JSON templates cover run_script, deploy_update, and deploy_package.
The run_script template supplies an empty run_script_params array unless
overridden. No reboot, update approval, target, or deployment scope is selected
automatically. Unknown template IDs are accepted with the caller's parameter
object. Server-specific required parameters are the caller's responsibility.

Supplied filters are structurally validated. Additional action parameters are
preserved, including properties not present in the local templates.

Build actions before the enclosing Automation definition. The usual flow is
**New-Action1AutomationActionFilter** -> this command ->
**New-Action1AutomationTarget** -> **New-Action1AutomationDefinition** or
**New-Action1AutomationScheduleDefinition** -> the appropriate submission command.
Targets and action filters serve different purposes: targets select endpoints;
filters are parameters of an action.

There is no existing-object parameter on this command. To reconstruct an action
from a retrieved Automation, pass its name, template_id, params, and optional id
explicitly. Alternatively, the enclosing definition builders can inherit the
entire existing action array without rebuilding each action.

The examples use API 4.0 and the configured default test organization.
The endpoint and Automation getters contact Action1 and require an authenticated
session; the builders themselves only construct objects locally. Configure
**Set-Action1Sign** before submitting an API 4.0 definition. See the related
submission command for the complete create/read/cleanup flow.

## EXAMPLES

### Example 1: Build an action and include it in a new run-now definition

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

Builds the filter and action before assembling the definition. No script-library
or package ID is invented. The action receives a new ID; the security-update scope
and reboot preference are explicit. Use **Start-Action1Automation** for submission,
instance discovery, read-back, and stop.

### Example 2: Reconstruct an action from an existing schedule

```powershell
$schedules = @(Get-Action1AutomationSchedules -ErrorAction Stop)
if ($schedules.Count -eq 0) { throw 'No source schedule was returned.' }
$source = Get-Action1AutomationSchedule `
    -AutomationInstanceId $schedules[0].id -ErrorAction Stop
$sourceActions = @($source.configuration.actions | Where-Object { $null -ne $_ })
if ($sourceActions.Count -eq 0) { throw 'The source schedule has no actions.' }
$sourceAction = $sourceActions[0]
$actionParameters = @{
    Name = $sourceAction.name
    TemplateId = $sourceAction.template_id
    Parameters = $sourceAction.params
}
if (-not [string]::IsNullOrWhiteSpace([string]$sourceAction.id)) {
    $actionParameters.ActionId = $sourceAction.id
}
$rebuiltAction = New-Action1AutomationAction @actionParameters
$definition = New-Action1AutomationScheduleDefinition -ExistingSchedule $source `
    -Actions @($rebuiltAction) -Settings DISABLED -ApiVersion '4.0'
```

There is no ExistingAction parameter. Pass the existing action fields explicitly.
A present action ID is preserved; omitting ActionId generates a new one. Supplying
Actions replaces the whole action array, so this example intentionally retains only
the first action. Reconstruct all actions when the full source sequence is required.

### Example 3: Reuse a newly built action in a disabled schedule definition

```powershell
$scheduleName = 'Documentation schedule ' + [guid]::NewGuid().ToString('N')
$definition = New-Action1AutomationScheduleDefinition -Name $scheduleName `
    -Actions @($action) -Endpoints @($target) -RetryMinutes 10 `
    -Settings DISABLED -SettingsTimezone UTC -ApiVersion '4.0' `
    -OrganizationId (Get-Action1DefaultOrgId)
```

Uses `$action` and `$target` from Example 1. Actions are components of either
run-now or schedule definitions; this builder does not create a remote action.
See **New-Action1AutomationSchedule** for creation, update, read-back, and removal.

## PARAMETERS

### -Name

The action display name. Must be nonempty and non-whitespace.

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

### -TemplateId

The API action template ID, such as run_script, deploy_update, or deploy_package. Unknown nonempty IDs are allowed.

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

### -Parameters

A dictionary or PSCustomObject mapped to params. JSON strings, scalars, and null are rejected. Nested filters must be arrays of valid filter objects.

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ActionId

The action identity. Any nonempty, non-whitespace string is accepted, including older prefixed IDs.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: A new GUID
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

Returns one PSCustomObject containing the action definition. Nested parameter
objects retain their supplied references and types.

## NOTES

Construction does not sign the action or create a remote resource. API 4.0
signing applies to the completed automation configuration. The local templates
are examples of supported structure, not exhaustive API schemas.

## RELATED LINKS

[New-Action1AutomationActionFilter](New-Action1AutomationActionFilter.md)
[New-Action1AutomationDefinition](New-Action1AutomationDefinition.md)
[New-Action1AutomationScheduleDefinition](New-Action1AutomationScheduleDefinition.md)
[New-Action1AutomationTarget](New-Action1AutomationTarget.md)
[Start-Action1Automation](Start-Action1Automation.md)
[New-Action1AutomationSchedule](New-Action1AutomationSchedule.md)
[Get-Action1Endpoints](../endpoint/Get-Action1Endpoints.md)
[Get-Action1EndpointGroups](../endpointgroup/Get-Action1EndpointGroups.md)
