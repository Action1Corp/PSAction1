---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# New-Action1AutomationDefinition

## SYNOPSIS

Builds an unsigned automation request from parameters or an existing object.

## SYNTAX

### Create (Default)

```powershell
New-Action1AutomationDefinition -Name <String> -Actions <Object[]> -Endpoints <Object[]> -RetryMinutes <Int32> [-ApiVersion <String>] [-OrganizationId <String>] [-ConfigurationId <String>] [-StartTime <DateTimeOffset>] [<CommonParameters>]
```

### FromAutomation

```powershell
New-Action1AutomationDefinition -ExistingAutomation <Object> [-Name <String>] [-Actions <Object[]>] [-Endpoints <Object[]>] [-RetryMinutes <Int32>] [-ApiVersion <String>] [-OrganizationId <String>] [-ConfigurationId <String>] [-StartTime <DateTimeOffset>] [<CommonParameters>]
```

## DESCRIPTION

Builds a request object without contacting Action1. Create populates a local
run-now JSON template. FromAutomation constructs a fresh top-level definition
from an existing instance, schedule, or prepared request, then applies only
parameters explicitly supplied by the caller. It does not decide whether the
result will be submitted through POST or PATCH.

API 3.0 output is flat. API 4.0 output contains configuration and root-level
endpoints. Nested API 4.0 sources use their configuration object; a flat instance
response supplies its available definition fields. Result pages and JSON strings
are rejected. The selected API version controls the output format; nested API 4.0
sources are not accepted as API 3.0 inputs.

Existing configuration fields, IDs, action IDs, start times, schedule settings,
and additional fields are retained unless explicitly overridden. Known response
metadata such as self, status, percent_completed, endpoint_results, end_time,
last_run, and next_run is excluded, as are signatures. The outer resource type
is not used as the configuration type. The caller is responsible for choosing
identities and timestamps appropriate to the intended request.

FromAutomation does not generate configuration IDs, action IDs, organization IDs,
or start times. Missing or invalid required API 4.0 identities must be supplied
explicitly using ConfigurationId and OrganizationId. In particular, a flat
AutomationInstance.id may contain an execution timestamp and cannot be used as
an API 4.0 configuration GUID without an explicit caller override.

Name, Actions, Endpoints, and RetryMinutes are mandatory only for Create.
FromAutomation inherits them; explicit parameters replace the corresponding
property or complete collection. A source with empty or missing actions requires
an explicit Actions value. A source without endpoints requires explicit Endpoints.
No follow-up API lookup is performed to retrieve missing action configuration.

Definitions containing settings are checked as schedules, allowing empty targets
only for DISABLED settings. Other definitions require nonempty targets. Nested
action, parameter, target, and extension objects are reused, so later edits to
those objects can affect the source. No deep copy or JSON round trip is performed.

Auto resolves the API version from the configured base URI at construction time.
An explicit version supports offline construction. RetryMinutes is a retry
deadline/maintenance window, not an interval between attempts, and is serialized
as a string.

## EXAMPLES

### Example 1: Build an API 3.0 request from scratch

```powershell
$action = New-Action1AutomationAction -Name 'Maintenance script' `
    -TemplateId run_script -Parameters @{ run_script_id = 'maintenance_script_id' }
$target = New-Action1AutomationTarget -Id 'maintenance_group' -Type EndpointGroup
$definition = New-Action1AutomationDefinition -Name 'Maintenance' `
    -Actions @($action) -Endpoints @($target) -RetryMinutes 60 -ApiVersion '3.0'
```

Builds a flat definition using the Create parameter set.

### Example 2: Build an API 4.0 request offline

```powershell
$action = New-Action1AutomationAction -Name 'Maintenance script' `
    -TemplateId run_script -Parameters @{ run_script_id = 'maintenance_script_id' }
$target = New-Action1AutomationTarget -Id 'maintenance_group' -Type EndpointGroup
$definition = New-Action1AutomationDefinition -Name 'Maintenance' `
    -Actions @($action) -Endpoints @($target) -RetryMinutes 60 -ApiVersion '4.0' `
    -OrganizationId '11111111-1111-1111-1111-111111111111'
```

Create generates a configuration ID and current UTC start time. The organization ID is illustrative. Signing is separate.

### Example 3: Reuse an instance and override selected properties

```powershell
$existing = Get-Action1AutomationInstance -AutomationInstanceId $instanceId
$definition = New-Action1AutomationDefinition -ExistingAutomation $existing `
    -Name 'Revised maintenance' -RetryMinutes 120 -ApiVersion '3.0'
```

Inherits the available fields, including the source ID and start time. If the getter returns empty actions, also supply Actions. The caller chooses the eventual submission operation.

### Example 4: Reuse a complete API 4.0 definition

```powershell
$existing = Get-Content -LiteralPath '.\AutomationDefinition.json' -Raw |
    ConvertFrom-Json
$definition = New-Action1AutomationDefinition -ExistingAutomation $existing `
    -RetryMinutes 120 -ApiVersion '4.0'
```

Changes only retry_minutes among inherited configuration fields. Existing IDs and start_time are preserved; old signatures are omitted.

### Example 5: Supply missing fields from an API 4.0 instance response

```powershell
$definition = New-Action1AutomationDefinition -ExistingAutomation $existing `
    -Actions @($action) -ConfigurationId $configurationId `
    -OrganizationId $organizationId -ApiVersion '4.0'
```

Uses caller-provided configuration identity and actions when the source contains only execution metadata or an empty action array.

## PARAMETERS

### -Name

The automation name. Required for Create; otherwise inherited and replaced only when explicitly supplied. Must be nonempty and non-whitespace.

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
Parameter Sets: FromAutomation
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Actions

The complete nonempty action array. Required for Create; otherwise inherited. Explicit use replaces the entire array. Null and malformed entries are rejected.

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
Parameter Sets: FromAutomation
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Endpoints

The explicit target array. Required for Create; otherwise inherited. An empty array is accepted only when the resulting definition is a DISABLED schedule. Null is rejected.

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
Parameter Sets: FromAutomation
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RetryMinutes

Positive retry deadline/maintenance window in minutes, serialized as retry_minutes string. Required for Create; otherwise inherited.

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
Parameter Sets: FromAutomation
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ApiVersion

Accepted values: Auto, 3.0, 4.0. Auto reads the configured API base URI. No network request is made.

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

API 4.0 only. Explicitly overrides organization_id. Create uses the local default organization when omitted. FromAutomation preserves the source and requires an explicit value if missing or invalid.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: Configured default for Create; source value for FromAutomation
Accept pipeline input: False
Accept wildcard characters: False
```

### -ConfigurationId

API 4.0 only. Explicitly overrides the configuration GUID. Create generates an ID when omitted. FromAutomation retains the source ID and never generates a replacement.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: A new GUID for Create; source ID for FromAutomation
Accept pipeline input: False
Accept wildcard characters: False
```

### -StartTime

API 4.0 only. Explicit values are converted to UTC and formatted as yyyy-MM-dd_HH-mm-ss. Create defaults to current UTC time. FromAutomation retains the original value or its absence.

```yaml
Type: DateTimeOffset
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: Current UTC time for Create; source value or absence for FromAutomation
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExistingAutomation

An instance, schedule, or prepared definition as a dictionary or PSCustomObject. Optional overrides supplement or replace its fields. Supply one object, not a result page, JSON string, or array.

```yaml
Type: Object
Parameter Sets: FromAutomation
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

Returns one PSCustomObject containing the unsigned version-specific request body,
not a JSON string or an API response. Nested objects may share source references.

## NOTES

The body version and organization must match the submission URI. The builder does
not infer POST/PATCH intent or reset inherited identities and timestamps.
Preserving, removing, or overriding IDs is the caller's responsibility.

A flat instance's execution ID is preserved as supplied, not parsed into a
configuration ID. API 4.0 GUID validation still applies; explicitly override the
configuration identity when necessary. Captured instance lists contain empty
actions arrays and cannot supply a complete action definition on their own.

Create still generates missing API 4.0 action IDs. FromAutomation retains the
presence or absence of existing action IDs. API 4.0 start_time, when present,
is checked for format; an absent source start time is not invented.

**Start-Action1Automation** signs the completed API 4.0 configuration and attaches
root-level signatures using credentials configured with **Set-Action1Sign**.
Changing a configuration requires a new signature. Generated Create timestamps
use UTC as the module convention; live API timezone/required-field behavior has
not been verified. Structural validation does not prove server acceptance.

## RELATED LINKS

[New-Action1AutomationAction](New-Action1AutomationAction.md)
[New-Action1AutomationTarget](New-Action1AutomationTarget.md)
[New-Action1AutomationScheduleDefinition](New-Action1AutomationScheduleDefinition.md)
[Get-Action1AutomationInstance](Get-Action1AutomationInstance.md)
[Start-Action1Automation](Start-Action1Automation.md)
