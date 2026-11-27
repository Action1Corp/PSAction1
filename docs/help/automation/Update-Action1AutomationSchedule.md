---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Update-Action1AutomationSchedule

## SYNOPSIS

Updates an automation schedule in the current Action1 organization.

## SYNTAX

```
Update-Action1AutomationSchedule [-AutomationInstanceId] <String> [[-AutomationScheduleDefinition] <Object>]
 [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

Updates an automation schedule by sending a PATCH request to
`/automations/schedules/{orgId}/{automationId}` using the module default
organization configured by **Set-Action1DefaultOrg**. The
**AutomationInstanceId** parameter supplies the `{automationId}` path segment
and identifies the schedule to update.

Supply **AutomationScheduleDefinition** as a PowerShell object containing the
request definition expected by the configured API version. API 3.0 uses a flat
definition; API 4.0 uses nested `configuration` and root-level `endpoints` and
signatures. **New-Action1AutomationScheduleDefinition -ExistingSchedule** can
copy a complete schedule and apply explicit overrides to build the unsigned
update body. For API 4.0, the command signs `configuration` using the session
credentials set by **Set-Action1Sign** and validates the attached signatures
before submission. To use a JSON string or file, first convert it to an object
with **ConvertFrom-Json**.

The configured region's base URI determines the API version. API 3.0 definitions
are passed unchanged to the shared request helper, which serializes them as JSON.
For API 4.0, signing updates the supplied object, generates a configuration GUID
if missing, and replaces existing signatures. Submission requires a nonempty
signature array with valid reference fields and signature fields (`alg`, `iat`,
`kid`, and `value`). This checks signature structure, not cryptographic validity.
Signing failures or invalid signatures prevent the request. The command does
not merge existing schedule values into the definition. Other API validation
errors are reported by the request helper.

Use **-WhatIf** to preview the operation without signing or sending the PATCH
request. Use **-Confirm** to request confirmation or **-Force** to suppress
confirmation prompts while still honoring **-WhatIf**.

Two construction paths produce an update body: retrieve the full schedule and
apply explicit overrides through ExistingSchedule, or build the full replacement
definition from scratch with actions, filters, real targets, settings, and the
stored ConfigurationId. A scratch rebuild does not inherit unspecified fields.
Keep `configuration.id` for the signed body and the schedule resource ID for
AutomationInstanceId in the request path; use the corresponding list/detail
getters to obtain both rather than treating an instance execution ID as either.

Verify changes with both **Get-Action1AutomationSchedules** and
**Get-Action1AutomationSchedule**, allowing bounded read-after-write delay.
The complete create/update/remove examples are in **New-Action1AutomationSchedule**.
This command updates a schedule definition, not an already running instance.

The API 4.0 examples use an authenticated session with an API 4.0 region,
a default test organization, and signing credentials configured through
**Set-Action1Credentials**, **Set-Action1Region**, **Set-Action1DefaultOrg**, and
**Set-Action1Sign**. The definition's API version and organization must match
the submission URI. The security-update action can install matching updates when
started; its `auto_reboot = 'no'` parameter disables automatic reboot. Schedules
in these examples remain `DISABLED`.

## EXAMPLES

### Example 1: Update a test schedule using its existing object

```powershell
# Supply the resource ID of a test schedule you intend to update.
$scheduleId = Read-Host 'Test schedule resource ID'
$details = Get-Action1AutomationSchedule -AutomationInstanceId $scheduleId -ErrorAction Stop
if ($null -eq $details) { throw 'The selected schedule was not returned.' }
$scheduleName = $details.configuration.name
$configurationId = [string]$details.configuration.id

# Inherit the stored identity and collections; override only these scalar fields.
$updateDefinition = New-Action1AutomationScheduleDefinition -ExistingSchedule $details `
    -Name "$scheduleName Updated" -RetryMinutes 11 -Settings DISABLED -SettingsTimezone UTC `
    -ApiVersion '4.0'

$updateResponse = Update-Action1AutomationSchedule -AutomationInstanceId $scheduleId `
    -AutomationScheduleDefinition $updateDefinition -Force -ErrorAction Stop

$verified = $false
for ($attempt = 1; $attempt -le 6; $attempt++) {
    $schedules = @(Get-Action1AutomationSchedules -ErrorAction Stop)
    $listed = @($schedules | Where-Object {
        $_.id -eq $scheduleId -and $_.configuration.name -ceq "$scheduleName Updated"
    })
    $updated = Get-Action1AutomationSchedule `
        -AutomationInstanceId $scheduleId -ErrorAction Stop
    if ($listed.Count -eq 1 -and $null -ne $updated -and
        $updated.configuration.id -eq $configurationId -and
        $updated.configuration.name -ceq "$scheduleName Updated" -and
        [string]$updated.configuration.retry_minutes -eq '11' -and
        $updated.configuration.settings -ceq 'DISABLED' -and
        $updated.configuration.settings_timezone -ceq 'UTC') {
        $verified = $true
        break
    }
    if ($attempt -lt 6) { Start-Sleep -Seconds 2 }
}
if (-not $verified) { throw 'Updated schedule fields did not read back before the timeout.' }
```

Reads the full object, rebuilds the unsigned definition with scalar overrides,
and submits PATCH. Actions, targets, and configuration identity are inherited.
The schedule stays disabled. Bounded list and detail reads verify the update.
The complete **New-Action1AutomationSchedule** examples create a disposable schedule
first and remove it afterward.

### Example 2: Replace the definition using builders from scratch

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

# Supply the resource ID of the test schedule whose full definition will be replaced.
$scheduleId = Read-Host 'Test schedule resource ID'
$details = Get-Action1AutomationSchedule -AutomationInstanceId $scheduleId -ErrorAction Stop
if ($null -eq $details) { throw 'The selected schedule was not returned.' }
$scheduleName = $details.configuration.name
$configurationId = [string]$details.configuration.id

# Rebuild the whole body with Create parameters; retain the stored configuration identity.
$updateDefinition = New-Action1AutomationScheduleDefinition `
    -Name "$scheduleName Updated" -Actions @($action) -Endpoints @($target) `
    -RetryMinutes 11 -Settings DISABLED -SettingsTimezone UTC -ApiVersion '4.0' `
    -OrganizationId (Get-Action1DefaultOrgId) -ConfigurationId $configurationId

$updateResponse = Update-Action1AutomationSchedule -AutomationInstanceId $scheduleId `
    -AutomationScheduleDefinition $updateDefinition -Force -ErrorAction Stop

$verified = $false
for ($attempt = 1; $attempt -le 6; $attempt++) {
    $schedules = @(Get-Action1AutomationSchedules -ErrorAction Stop)
    $listed = @($schedules | Where-Object {
        $_.id -eq $scheduleId -and $_.configuration.name -ceq "$scheduleName Updated"
    })
    $updated = Get-Action1AutomationSchedule `
        -AutomationInstanceId $scheduleId -ErrorAction Stop
    if ($listed.Count -eq 1 -and $null -ne $updated -and
        $updated.configuration.id -eq $configurationId -and
        $updated.configuration.name -ceq "$scheduleName Updated" -and
        [string]$updated.configuration.retry_minutes -eq '11' -and
        $updated.configuration.settings -ceq 'DISABLED' -and
        $updated.configuration.settings_timezone -ceq 'UTC') {
        $verified = $true
        break
    }
    if ($attempt -lt 6) { Start-Sleep -Seconds 2 }
}
if (-not $verified) { throw 'Updated schedule fields did not read back before the timeout.' }
```

Builds a new filter, action, and real target, then uses the Create parameter set for
the replacement body. Retaining the stored configuration GUID is explicit. This is
a full definition, not a sparse merge: fields and collections not supplied by this
flow are not inherited from the selected schedule.

### Example 3: Rebuild a saved schedule definition and preview an update

```powershell
$saved = Get-Content -LiteralPath '.\AutomationScheduleDefinition.json' -Raw | ConvertFrom-Json
$scheduleId = Read-Host 'Test schedule resource ID'
$current = Get-Action1AutomationSchedule -AutomationInstanceId $scheduleId -ErrorAction Stop
if ($null -eq $current) { throw 'The selected schedule was not returned.' }
$updateDefinition = New-Action1AutomationScheduleDefinition -ExistingSchedule $saved `
    -ConfigurationId $current.configuration.id -OrganizationId (Get-Action1DefaultOrgId) `
    -Settings DISABLED -SettingsTimezone UTC -ApiVersion '4.0'
Update-Action1AutomationSchedule -AutomationInstanceId $scheduleId `
    -AutomationScheduleDefinition $updateDefinition -Force -WhatIf
```

Uses the stored resource identity and the saved definition content. WhatIf skips
signing and PATCH but does not skip the preceding file read, GET, or builder calls.

## PARAMETERS

### -AutomationInstanceId

Specifies the ID of the automation schedule to update. Despite the parameter
name, this value identifies the schedule and supplies the `{automationId}` path
segment. The value cannot be null or empty.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AutomationScheduleDefinition

Specifies the automation schedule definition as a PowerShell object, such as a
hashtable or an object returned by **ConvertFrom-Json**. The supplied value must
not be null or empty. Although optional at parameter binding, a definition must
be supplied to send an update request. If omitted, the command reports an error
without sending a request; **-WhatIf** can preview the operation without one.

The object supplies the PATCH body and is signed in place for API 4.0.
Use the definition schema expected by the configured API version. API 3.0 keeps
actions and settings at the root; API 4.0 places them inside `configuration`.
The body version and organization must match the request URI. Configure session
signing credentials with **Set-Action1Sign** for API 4.0; the command replaces
prior signatures automatically.

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Confirm

Prompts you for confirmation before running the cmdlet.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Force

Suppresses confirmation prompts. This parameter does not override **-WhatIf**.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIf

Shows what would happen if the cmdlet runs without sending the PATCH request.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: wi

Required: False
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

### System.Object

Returns the Action1 API response for the updated automation schedule without
changing its properties.

## NOTES

Requires the default Action1 organization to be configured with
**Set-Action1DefaultOrg**. The request URL uses that default organization.

The command reports an error if the request helper returns a null response.

## RELATED LINKS

[New-Action1AutomationScheduleDefinition](New-Action1AutomationScheduleDefinition.md)
[Get-Action1AutomationSchedules](Get-Action1AutomationSchedules.md)
[New-Action1AutomationSchedule](New-Action1AutomationSchedule.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
[Set-Action1Sign](../configuration/Set-Action1Sign.md)
[Get-Action1AutomationSchedule](Get-Action1AutomationSchedule.md)
[New-Action1AutomationActionFilter](New-Action1AutomationActionFilter.md)
[New-Action1AutomationAction](New-Action1AutomationAction.md)
[New-Action1AutomationTarget](New-Action1AutomationTarget.md)
[Remove-Action1AutomationSchedule](Remove-Action1AutomationSchedule.md)
[Get-Action1Endpoints](../endpoint/Get-Action1Endpoints.md)
[Get-Action1EndpointGroups](../endpointgroup/Get-Action1EndpointGroups.md)
