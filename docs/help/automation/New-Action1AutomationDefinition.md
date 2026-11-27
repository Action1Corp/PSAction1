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

A run-now Automation definition is the request object used to create an
Automation instance with **Start-Action1Automation**. There is no separate public
Automation Instance Definition builder: this command supplies that role. The
instance is the execution resource returned by the service and read with
**Get-Action1AutomationInstance**. Its resource ID is used by
**Stop-Action1Automation**, while the API 4.0 `configuration.id` identifies the
signed configuration. Do not interchange those IDs.

The construction flow is filter -> action -> real target reference -> unsigned
definition -> Start -> instance discovery -> detail read -> Stop. For a source
instance, retrieve its details first, then use ExistingAutomation and supply
missing actions or targets. For a separate run, explicitly choose a fresh
configuration GUID and current start time. See the complete examples below.

The examples use API 4.0 and the configured default test organization.
The endpoint and Automation getters contact Action1 and require an authenticated
session; the builders themselves only construct objects locally. Configure
**Set-Action1Sign** before submitting an API 4.0 definition. See the related
submission command for the complete create/read/cleanup flow.

## EXAMPLES

### Example 1: Build a run-now Automation definition from scratch

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

$definition | ConvertTo-Json -Depth 100
```

Selects a real connected endpoint, then builds filter -> action -> target collection ->
run-now definition. No instance is created until **Start-Action1Automation** is called.
Create generates `configuration.id` when omitted and uses the supplied UTC start time.

### Example 2: Build from an existing instance with a fresh identity and start time

```powershell
$instances = @(
    @(Get-Action1AutomationInstances -ErrorAction Stop) +
    @(Get-Action1AutomationInstances -NotCompleted -ErrorAction Stop) |
        Sort-Object -Property id -Unique
)
if ($instances.Count -eq 0) { throw 'No source instance was returned.' }
$source = Get-Action1AutomationInstance `
    -AutomationInstanceId $instances[0].id -ErrorAction Stop

$runName = 'Documentation cloned run ' + [guid]::NewGuid().ToString('N')
$definition = New-Action1AutomationDefinition -ExistingAutomation $source `
    -Name $runName -Actions @($action) -Endpoints @($target) -RetryMinutes 10 `
    -ApiVersion '4.0' -OrganizationId (Get-Action1DefaultOrgId) `
    -ConfigurationId ([guid]::NewGuid().ToString()) `
    -StartTime ([DateTimeOffset]::UtcNow)
```

Uses `$action` and `$target` from Example 1 as explicit replacements. This also covers
instance responses whose actions or targets are empty. The source execution ID is
not treated as a configuration GUID. Other available definition fields are inherited;
response metadata and signatures are omitted.

### Example 3: Start the definition, discover its instance, read it, and stop it

```powershell
# Save both completed and active IDs before submitting the definition.
$beforeIds = @(
    @(Get-Action1AutomationInstances -ErrorAction Stop) +
    @(Get-Action1AutomationInstances -NotCompleted -ErrorAction Stop) |
        Select-Object -ExpandProperty id -Unique
)
$startResponse = Start-Action1Automation -AutomationDefinition $definition `
    -Force -ErrorAction Stop

$created = $null
for ($attempt = 1; $attempt -le 6; $attempt++) {
    $instances = @(
        @(Get-Action1AutomationInstances -ErrorAction Stop) +
        @(Get-Action1AutomationInstances -NotCompleted -ErrorAction Stop) |
            Sort-Object -Property id -Unique
    )
    $matches = @($instances | Where-Object {
        $itemName = if ($_.configuration.name) { $_.configuration.name } else { $_.name }
        $_.id -notin $beforeIds -and $itemName -ceq $runName
    })
    if ($matches.Count -gt 1) { throw 'More than one fresh run matches this name.' }
    if ($matches.Count -eq 1) { $created = $matches[0]; break }
    if ($attempt -lt 6) { Start-Sleep -Seconds 2 }
}
if ($null -eq $created) { throw 'The new run did not appear before the timeout.' }
$instanceId = [string]$created.id
$details = Get-Action1AutomationInstance -AutomationInstanceId $instanceId -ErrorAction Stop
if ($null -eq $details -or $details.id -ne $instanceId) { throw 'Instance read-back failed.' }

$stopResponse = Stop-Action1Automation -AutomationInstanceId $instanceId `
    -Force -ErrorAction Stop
```

Continues with `$definition` and `$runName` from Example 1 or 2. List discovery uses
both completed and active runs because the default getter returns completed runs.
The fresh instance ID comes from the list difference and exact generated name,
rather than from `configuration.id` or an assumed submission-response field.
Stopping leaves execution history readable and does not undo completed actions.

### Example 4: Rebuild an unsigned definition from saved JSON

```powershell
$saved = Get-Content -LiteralPath '.\AutomationDefinition.json' -Raw | ConvertFrom-Json
$definition = New-Action1AutomationDefinition -ExistingAutomation $saved `
    -Name ('Rebuilt run ' + [guid]::NewGuid().ToString('N')) -RetryMinutes 11 `
    -ConfigurationId ([guid]::NewGuid().ToString()) `
    -StartTime ([DateTimeOffset]::UtcNow) -ApiVersion '4.0'
```

Requires a saved API 4.0 definition with usable actions, targets, and organization ID.
A new configuration identity and timestamp are explicit caller choices. The builder
returns an unsigned object; submission signs the final configuration again.

### Example 5: Build the equivalent API 3.0 body

```powershell
$legacyDefinition = New-Action1AutomationDefinition -Name 'Legacy test run' `
    -Actions @($action) -Endpoints @($target) -RetryMinutes 10 -ApiVersion '3.0'
```

Uses the action and real target from Example 1. API 3.0 output is flat; omit the
API 4.0-only OrganizationId, ConfigurationId, and StartTime parameters. Submit
this body only through a session configured for API 3.0.

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
use UTC as the module convention. The service validates submitted action
parameters and required fields; structural validation does not prove server acceptance.

## RELATED LINKS

[New-Action1AutomationAction](New-Action1AutomationAction.md)
[New-Action1AutomationTarget](New-Action1AutomationTarget.md)
[New-Action1AutomationScheduleDefinition](New-Action1AutomationScheduleDefinition.md)
[Get-Action1AutomationInstance](Get-Action1AutomationInstance.md)
[Start-Action1Automation](Start-Action1Automation.md)
[New-Action1AutomationActionFilter](New-Action1AutomationActionFilter.md)
[Get-Action1AutomationInstances](Get-Action1AutomationInstances.md)
[Stop-Action1Automation](Stop-Action1Automation.md)
[Get-Action1Endpoints](../endpoint/Get-Action1Endpoints.md)
[Get-Action1EndpointGroups](../endpointgroup/Get-Action1EndpointGroups.md)
