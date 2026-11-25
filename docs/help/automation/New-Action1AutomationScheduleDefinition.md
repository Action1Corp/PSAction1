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

## EXAMPLES

### Example 1: Build a disabled schedule from scratch

```powershell
$action = New-Action1AutomationAction -Name 'Maintenance script' `
    -TemplateId run_script -Parameters @{ run_script_id = 'maintenance_script_id' }
$definition = New-Action1AutomationScheduleDefinition -Name 'Maintenance' `
    -Actions @($action) -Endpoints @() -RetryMinutes 60 -Settings DISABLED `
    -ApiVersion '3.0'
```

Builds a flat disabled definition with UTC settings_timezone.

### Example 2: Override one property from a retrieved schedule

```powershell
$schedule = Get-Action1AutomationSchedules | Select-Object -First 1
$definition = New-Action1AutomationScheduleDefinition `
    -ExistingSchedule $schedule -RetryMinutes 120
```

Preserves source identities and unspecified fields. The caller chooses the submission command and is responsible for the IDs.

### Example 3: Use the ExistingAutomation alias

```powershell
$definition = New-Action1AutomationScheduleDefinition `
    -ExistingAutomation $schedule -Name 'Revised maintenance'
```

Uses exactly the same inheritance rules as ExistingSchedule. This alias does not trigger identity regeneration.

### Example 4: Supply scheduling fields for an instance

```powershell
$existing = Get-Action1AutomationInstance -AutomationInstanceId $instanceId
$definition = New-Action1AutomationScheduleDefinition `
    -ExistingAutomation $existing -Actions @($action) `
    -Settings 'ENABLED MONTHLY:4 AT:11-17-00' -SettingsTimezone UTC `
    -ApiVersion '3.0'
```

Retains the available instance definition fields and source ID. Supply missing API 4.0 configuration identity explicitly when using API 4.0.

### Example 5: Explicitly override API 4.0 identity

```powershell
$definition = New-Action1AutomationScheduleDefinition `
    -ExistingSchedule $schedule -ApiVersion '4.0' `
    -ConfigurationId '33333333-3333-3333-3333-333333333333'
```

Overrides configuration.id because the caller supplied ConfigurationId. The builder makes no POST/PATCH choice.

### Example 6: Clear targets while disabling a schedule

```powershell
$definition = New-Action1AutomationScheduleDefinition `
    -ExistingSchedule $schedule -Settings DISABLED -Endpoints @()
```

Explicitly clears targets. Omitting Endpoints preserves them.

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

No signatures are inherited. Sign the completed API 4.0 configuration and attach
root signatures before submission. Existing action IDs, including their absence,
are retained; Create continues to generate IDs for raw new API 4.0 actions.

API 4.0 schedule-create structure is inferred from captured GET/PATCH bodies and
has not been validated with a live create request. Server scheduling grammar and
sparse PATCH semantics are outside this builder's contract.

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
