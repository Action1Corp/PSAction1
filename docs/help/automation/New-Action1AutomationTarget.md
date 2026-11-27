---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# New-Action1AutomationTarget

## SYNOPSIS

Builds an automation endpoint or endpoint-group reference locally.

## SYNTAX

```powershell
New-Action1AutomationTarget -Id <String> -Type <String> [<CommonParameters>]
```

## DESCRIPTION

Creates an object with `id` and `type` for an automation's `endpoints` array.
No API request is made. Individual endpoint IDs must be GUIDs. Endpoint-group IDs
can be nonempty strings, including the explicit all-endpoints group ID `ALL`.
The returned type is normalized to `Endpoint` or `EndpointGroup`.

For a new definition, obtain an actual ID from **Get-Action1Endpoints** or
**Get-Action1EndpointGroups**, build this reference, and pass it as an element of
Endpoints to **New-Action1AutomationDefinition** or
**New-Action1AutomationScheduleDefinition**. The target builder does not look up
or create the endpoint or group.

There is no existing-object parameter. A stored target can be reconstructed by
passing its id and type explicitly, or inherited through the enclosing builder's
ExistingAutomation/ExistingSchedule parameter. Explicit Endpoints replaces the
whole target collection. Submission creates an instance or schedule, not a new
endpoint or endpoint group.

The examples use API 4.0 and the configured default test organization.
The endpoint and Automation getters contact Action1 and require an authenticated
session; the builders themselves only construct objects locally. Configure
**Set-Action1Sign** before submitting an API 4.0 definition. See the related
submission command for the complete create/read/cleanup flow.

## EXAMPLES

### Example 1: Select a real connected endpoint and build a definition

```powershell
$endpoints = @(Get-Action1Endpoints -Status Connected -ErrorAction Stop)
if ($endpoints.Count -eq 0) { throw 'No connected test endpoint was returned.' }
$target = New-Action1AutomationTarget -Id $endpoints[0].id -Type Endpoint

$filter = New-Action1AutomationActionFilter -Name update_types `
    -Values 'Security Updates' -Operator include
$action = New-Action1AutomationAction -Name 'Security updates' `
    -TemplateId deploy_update -Parameters @{
        scope = 'MatchingFilters'
        filters = @($filter)
        reboot_options = @{ auto_reboot = 'no' }
    }

$runName = 'Documentation run ' + [guid]::NewGuid().ToString('N')
$definition = New-Action1AutomationDefinition -Name $runName `
    -Actions @($action) -Endpoints @($target) -RetryMinutes 10 `
    -ApiVersion '4.0' -OrganizationId (Get-Action1DefaultOrgId) `
    -StartTime ([DateTimeOffset]::UtcNow)
```

Resolves a real endpoint with the public getter before building its reference.
The target belongs in the definition Endpoints array, separately from actions and
action filters. Starting the definition executes its actions on that target.

### Example 2: Select an endpoint group returned by the service

```powershell
$groups = @(Get-Action1EndpointGroups -ErrorAction Stop)
if ($groups.Count -eq 0) { throw 'No endpoint group was returned.' }
$groupTarget = New-Action1AutomationTarget -Id $groups[0].id -Type EndpointGroup
$scheduleName = 'Documentation group schedule ' + [guid]::NewGuid().ToString('N')
$definition = New-Action1AutomationScheduleDefinition -Name $scheduleName `
    -Actions @($action) -Endpoints @($groupTarget) -RetryMinutes 10 `
    -Settings DISABLED -SettingsTimezone UTC -ApiVersion '4.0' `
    -OrganizationId (Get-Action1DefaultOrgId)
```

Uses `$action` from Example 1. The ID comes from the endpoint-group getter rather
than a made-up name or automatic ALL selection. The disabled definition can be
submitted through **New-Action1AutomationSchedule**.

### Example 3: Reconstruct a stored target reference from an existing schedule

```powershell
$schedules = @(Get-Action1AutomationSchedules -ErrorAction Stop)
if ($schedules.Count -eq 0) { throw 'No source schedule was returned.' }
$source = Get-Action1AutomationSchedule `
    -AutomationInstanceId $schedules[0].id -ErrorAction Stop
$sourceTargets = @($source.endpoints | Where-Object { $null -ne $_ })
if ($sourceTargets.Count -eq 0) { throw 'The source schedule has no targets.' }
$sourceTarget = $sourceTargets[0]
$target = New-Action1AutomationTarget -Id $sourceTarget.id -Type $sourceTarget.type
$definition = New-Action1AutomationScheduleDefinition -ExistingSchedule $source `
    -Endpoints @($target) -Settings DISABLED -ApiVersion '4.0'
```

There is no ExistingTarget parameter. The existing ID and type are passed
explicitly. This replaces the entire target array with the first stored reference.
The builder checks the reference shape; use the endpoint or endpoint-group getter
again when current target existence must be verified.

## PARAMETERS

### -Id

The endpoint GUID or endpoint-group ID. Null, empty, and whitespace values are rejected.

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

### -Type

The target type. Accepted values: Endpoint, EndpointGroup.

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

Returns one PSCustomObject containing `id` and `type`.

## NOTES

This command constructs a reference; it does not verify that the target exists.
It does not require credentials, a region, or a default organization.

## RELATED LINKS

[New-Action1AutomationDefinition](New-Action1AutomationDefinition.md)
[New-Action1AutomationScheduleDefinition](New-Action1AutomationScheduleDefinition.md)
[New-Action1AutomationAction](New-Action1AutomationAction.md)
[Start-Action1Automation](Start-Action1Automation.md)
[New-Action1AutomationSchedule](New-Action1AutomationSchedule.md)
[Get-Action1Endpoints](../endpoint/Get-Action1Endpoints.md)
[Get-Action1EndpointGroups](../endpointgroup/Get-Action1EndpointGroups.md)
