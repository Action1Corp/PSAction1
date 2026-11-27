---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# New-Action1AutomationScheduleDefinition

## SYNOPSIS

Builds an unsigned schedule definition from parameters or an existing automation.

## SYNTAX

### Create (Default)

```powershell
New-Action1AutomationScheduleDefinition -Name <String> -Actions <Object[]> -Endpoints <Object[]> -RetryMinutes <Int32> -Settings <String> [-SettingsTimezone <String>] [-ApiVersion <String>] [-OrganizationId <String>] [-ConfigurationId <String>] [<CommonParameters>]
```

### FromSchedule

```powershell
New-Action1AutomationScheduleDefinition -ExistingSchedule <Object> [-Name <String>] [-Actions <Object[]>] [-Endpoints <Object[]>] [-RetryMinutes <Int32>] [-Settings <String>] [-SettingsTimezone <String>] [-ApiVersion <String>] [-OrganizationId <String>] [-ConfigurationId <String>] [<CommonParameters>]
```

## DESCRIPTION

Builds a schedule request object without contacting Action1. Create populates a
local template. FromSchedule constructs a fresh top-level configuration from
ExistingSchedule, also accepted as ExistingAutomation, and applies only explicit
parameter overrides. The builder does not decide whether the result will be used
for POST or PATCH and does not reset source identities.

API 3.0 output is flat. API 4.0 places the definition inside configuration, with
endpoints at the request root. Existing configuration fields, including IDs,
action IDs, timestamps, schedule settings, and additional properties, are retained.
Known execution/response metadata and signatures are omitted. API 4.0 schedules
must supply nested configuration; flat instance responses may be used when the
caller supplies missing configuration identity and schedule fields.

Omitted parameters preserve source values or their absence. Explicit parameters
replace the corresponding property or complete action/target array. Existing
configuration and organization IDs may be explicitly overridden. Missing required
fields must be supplied by the caller; creation defaults such as UTC timezone,
current default organization, and generated IDs do not fill an existing object.

Actions must be nonempty. Endpoints may be empty only when settings is DISABLED.
A source with empty actions requires explicit Actions. An instance without
schedule settings requires explicit Settings and SettingsTimezone. This command
does not retrieve missing data or perform a sparse PATCH.

Scalar overrides apply to a fresh top-level configuration. Nested action,
parameter, target, and extension objects are reused, so later edits can affect
the source. No deep copy or JSON round trip is performed.

The construction flow is filter -> action -> real target reference -> unsigned
schedule definition. **New-Action1AutomationSchedule** submits it through POST;
**Update-Action1AutomationSchedule** submits it through PATCH. Both Create and
FromSchedule can supply either operation. For cloning through POST, explicitly
assign a fresh API 4.0 ConfigurationId. For PATCH, retain the stored
`configuration.id`, including when rebuilding the whole body from scratch.

The schedule resource ID returned by the list/detail getters is passed as
AutomationInstanceId to schedule GET, update, and remove commands. It is distinct
in purpose from the configuration GUID referenced by the signature, and from an
Automation instance execution ID. See **New-Action1AutomationSchedule** for both
complete CRUD paths, including verification after removal.

The examples use API 4.0 and the configured default test organization.
The endpoint and Automation getters contact Action1 and require an authenticated
session; the builders themselves only construct objects locally. Configure
**Set-Action1Sign** before submitting an API 4.0 definition. See the related
submission command for the complete create/read/cleanup flow.

## EXAMPLES

### Example 1: Build a disabled schedule definition from scratch

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

$scheduleName = 'Documentation schedule ' + [guid]::NewGuid().ToString('N')
$definition = New-Action1AutomationScheduleDefinition -Name $scheduleName `
    -Actions @($action) -Endpoints @($target) -RetryMinutes 10 `
    -Settings DISABLED -SettingsTimezone UTC -ApiVersion '4.0' `
    -OrganizationId (Get-Action1DefaultOrgId)

$definition | ConvertTo-Json -Depth 100
```

Builds every component explicitly and keeps the schedule disabled. Create generates
the configuration GUID when omitted. **New-Action1AutomationSchedule** creates
the remote schedule; this builder only returns the unsigned definition.

### Example 2: Clone a retrieved schedule for a new resource

```powershell
$schedules = @(Get-Action1AutomationSchedules -ErrorAction Stop)
if ($schedules.Count -eq 0) { throw 'No source schedule was returned.' }
$source = Get-Action1AutomationSchedule `
    -AutomationInstanceId $schedules[0].id -ErrorAction Stop

$scheduleName = 'Documentation cloned schedule ' + [guid]::NewGuid().ToString('N')
$definition = New-Action1AutomationScheduleDefinition -ExistingSchedule $source `
    -Name $scheduleName -Settings DISABLED -SettingsTimezone UTC -RetryMinutes 10 `
    -ApiVersion '4.0' -OrganizationId (Get-Action1DefaultOrgId) `
    -ConfigurationId ([guid]::NewGuid().ToString())
```

Reads the full schedule by its resource ID, then assigns a fresh configuration GUID
and generated name before POST. Usable actions and targets are inherited. If the
source lacks them, also supply `-Actions @($action) -Endpoints @($target)` from
Example 1. The source schedule itself is not updated.

### Example 3: Build an update from an existing schedule without resetting identity

```powershell
$scheduleId = Read-Host 'Test schedule resource ID'
$details = Get-Action1AutomationSchedule `
    -AutomationInstanceId $scheduleId -ErrorAction Stop
$scheduleName = $details.configuration.name
# Inherit the stored identity and collections; override only these scalar fields.
$updateDefinition = New-Action1AutomationScheduleDefinition -ExistingSchedule $details `
    -Name "$scheduleName Updated" -RetryMinutes 11 -Settings DISABLED -SettingsTimezone UTC `
    -ApiVersion '4.0'
$response = Update-Action1AutomationSchedule -AutomationInstanceId $scheduleId `
    -AutomationScheduleDefinition $updateDefinition -Force -ErrorAction Stop
```

Uses the selected test schedule. The **New-Action1AutomationSchedule** workflow
shows creation and cleanup of a disposable resource for the same operation.
Omitting ConfigurationId preserves `configuration.id`. `-ExistingAutomation`
is an alias for `-ExistingSchedule` with the same inheritance rules. The update
command signs the changed API 4.0 configuration before sending PATCH.

### Example 4: Build an update from scratch while preserving the stored identity

```powershell
$scheduleId = Read-Host 'Test schedule resource ID'
$details = Get-Action1AutomationSchedule `
    -AutomationInstanceId $scheduleId -ErrorAction Stop
$scheduleName = $details.configuration.name
$configurationId = [string]$details.configuration.id
# Rebuild the whole body with Create parameters; retain the stored configuration identity.
$updateDefinition = New-Action1AutomationScheduleDefinition `
    -Name "$scheduleName Updated" -Actions @($action) -Endpoints @($target) `
    -RetryMinutes 11 -Settings DISABLED -SettingsTimezone UTC -ApiVersion '4.0' `
    -OrganizationId (Get-Action1DefaultOrgId) -ConfigurationId $configurationId
$response = Update-Action1AutomationSchedule -AutomationInstanceId $scheduleId `
    -AutomationScheduleDefinition $updateDefinition -Force -ErrorAction Stop
```

Uses the Create parameter set even though the result is submitted through PATCH.
Supply the full action and target arrays from Example 1, all schedule settings,
and the stored configuration GUID. The schedule resource ID remains in the
update command parameter. The builder does not choose POST or PATCH.

### Example 5: Build a disabled API 3.0 schedule

```powershell
$legacyDefinition = New-Action1AutomationScheduleDefinition -Name 'Legacy test schedule' `
    -Actions @($action) -Endpoints @($target) -RetryMinutes 10 `
    -Settings DISABLED -SettingsTimezone UTC -ApiVersion '3.0'
```

Uses the components from Example 1 and returns a flat unsigned body. API 3.0
does not accept OrganizationId or ConfigurationId on this builder. Use an API 3.0
session for submission. See **New-Action1AutomationSchedule** for full CRUD flows.

## PARAMETERS

### -Name

The nonempty schedule name. Required for Create; otherwise inherited or explicitly replaced.

```yaml
Type: String
Parameter Sets: Create
Aliases: 

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

```yaml
Type: String
Parameter Sets: FromSchedule
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Actions

The complete nonempty action array. Required for Create; otherwise inherited or explicitly replaced. Null and malformed entries are rejected.

```yaml
Type: Object[]
Parameter Sets: Create
Aliases: 

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

```yaml
Type: Object[]
Parameter Sets: FromSchedule
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Endpoints

The explicit target array. Required for Create; otherwise inherited or explicitly replaced. Empty is supported only for DISABLED settings. Null is rejected.

```yaml
Type: Object[]
Parameter Sets: Create
Aliases: 

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

```yaml
Type: Object[]
Parameter Sets: FromSchedule
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RetryMinutes

Positive retry deadline/maintenance window in minutes, serialized as a string. Required for Create; otherwise inherited.

```yaml
Type: Int32
Parameter Sets: Create
Aliases: 

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

```yaml
Type: Int32
Parameter Sets: FromSchedule
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Settings

The nonempty API scheduling expression, such as DISABLED or ENABLED MONTHLY:4 AT:11-17-00. Required for Create; otherwise inherited. Full scheduling grammar is not validated locally.

```yaml
Type: String
Parameter Sets: Create
Aliases: 

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

```yaml
Type: String
Parameter Sets: FromSchedule
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SettingsTimezone

The nonempty API timezone. Defaults to UTC only for Create. FromSchedule preserves the source value or absence unless explicitly supplied.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: UTC for Create; source value or absence for FromSchedule
Accept pipeline input: False
Accept wildcard characters: False
```

### -ApiVersion

Accepted values: Auto, 3.0, 4.0. Auto resolves from the configured base URI. Nested API 4.0 sources are rejected for API 3.0 output.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: Auto
Accept pipeline input: False
Accept wildcard characters: False
```

### -OrganizationId

API 4.0 only. Explicitly overrides organization_id. Create uses the local default when omitted. FromSchedule preserves the source and requires an explicit value if missing or invalid.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: Configured default for Create; source value for FromSchedule
Accept pipeline input: False
Accept wildcard characters: False
```

### -ConfigurationId

API 4.0 only. Explicitly overrides configuration.id. Create generates an ID when omitted. FromSchedule retains the source ID and never generates a replacement.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: A new GUID for Create; source ID for FromSchedule
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExistingSchedule

One existing instance, schedule, or prepared definition as a dictionary or PSCustomObject. ExistingAutomation is an alias with identical behavior. Result pages, arrays, and JSON strings are rejected.

```yaml
Type: Object
Parameter Sets: FromSchedule
Aliases: ExistingAutomation

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

Returns one PSCustomObject containing the unsigned version-specific request body,
not a JSON string or an API response. Nested objects may share source references.

## NOTES

The caller is responsible for retaining or overriding IDs according to the intended
submission. API 3.0 source IDs are preserved as root id properties. API 4.0 GUID
validation still applies; composite instance execution IDs require an explicit
ConfigurationId override, and missing organization IDs require OrganizationId.

No signatures are inherited. **New-Action1AutomationSchedule** and
**Update-Action1AutomationSchedule** sign API 4.0 configurations before submission
using credentials configured with **Set-Action1Sign**. Existing action IDs,
including their absence, are retained; Create continues to generate IDs for raw
new API 4.0 actions.

Server scheduling grammar and sparse PATCH semantics are outside this builder's
contract. The builder checks structure; the service validates submitted action
parameters and schedule settings.

Update-Action1AutomationSchedule uses AutomationInstanceId for the schedule
resource ID in the request path. The signature references configuration.id.
Ensure the prepared body and configured request URI use the same organization
and API version. The builder does not migrate API-specific action semantics.

## RELATED LINKS

[New-Action1AutomationDefinition](New-Action1AutomationDefinition.md)
[New-Action1AutomationAction](New-Action1AutomationAction.md)
[New-Action1AutomationTarget](New-Action1AutomationTarget.md)
[New-Action1AutomationSchedule](New-Action1AutomationSchedule.md)
[Update-Action1AutomationSchedule](Update-Action1AutomationSchedule.md)
[Get-Action1AutomationSchedules](Get-Action1AutomationSchedules.md)
[Get-Action1AutomationInstance](Get-Action1AutomationInstance.md)
[New-Action1AutomationActionFilter](New-Action1AutomationActionFilter.md)
[Get-Action1AutomationSchedule](Get-Action1AutomationSchedule.md)
[Remove-Action1AutomationSchedule](Remove-Action1AutomationSchedule.md)
[Get-Action1Endpoints](../endpoint/Get-Action1Endpoints.md)
[Get-Action1EndpointGroups](../endpointgroup/Get-Action1EndpointGroups.md)
