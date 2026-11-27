---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# New-Action1AutomationSchedule

## SYNOPSIS

Creates an automation schedule in the current Action1 organization.

## SYNTAX

```
New-Action1AutomationSchedule [-AutomationScheduleDefinition] <Object> [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

Creates an automation schedule by sending a POST request to
`/automations/schedules/{orgId}` using the module default organization configured
by **Set-Action1DefaultOrg**.

Supply **AutomationScheduleDefinition** as a PowerShell object containing the
request definition expected by the configured API version. API 3.0 uses a flat
definition; API 4.0 uses nested `configuration` and root-level `endpoints` and
signatures. Build the unsigned object with **New-Action1AutomationScheduleDefinition**.
For API 4.0, the command signs `configuration` using the session credentials set
by **Set-Action1Sign** and validates the attached signatures before submission.
To use a JSON string or file, first convert it to an object with **ConvertFrom-Json**.

The configured region's base URI determines the API version. API 3.0 definitions
are passed unchanged to the shared request helper, which serializes them as JSON.
For API 4.0, signing updates the supplied object, generates a configuration GUID
if missing, and replaces existing signatures. Submission requires a nonempty
signature array with valid reference fields and signature fields (`alg`, `iat`,
`kid`, and `value`). This checks signature structure, not cryptographic validity.
Signing failures or invalid signatures prevent the request. Other API validation
errors are reported by the request helper.

The command prompts for confirmation before creating an automation schedule.
Use **-WhatIf** to preview the operation without signing or sending the POST
request. Use **-Force** to suppress confirmation prompts while still honoring
**-WhatIf**.

The full flow is list -> build -> create -> discover the fresh schedule ID ->
read -> build updated definition -> update -> verify list and detail reads ->
remove -> verify list absence and direct GET failure. Build from scratch with
the action/filter/target builders, or retrieve a full schedule and use
**New-Action1AutomationScheduleDefinition -ExistingSchedule** to clone it.

For a clone, explicitly generate a new configuration GUID before POST. For an
update, retain the stored configuration GUID and pass the schedule resource ID
to **Update-Action1AutomationSchedule -AutomationInstanceId**. Neither the
builder nor the submission response should be used to guess an execution ID.
After schedule removal, the observed API 4.0 behavior is HTTP 400 with a matching
not-found message, surfaced by the module as Action1ApiRequestHttp400 when
ErrorAction is Stop. HTTP 200 is not a successful post-removal result.

The API 4.0 examples use an authenticated session with an API 4.0 region,
a default test organization, and signing credentials configured through
**Set-Action1Credentials**, **Set-Action1Region**, **Set-Action1DefaultOrg**, and
**Set-Action1Sign**. The definition's API version and organization must match
the submission URI. The security-update action can install matching updates when
started; its `auto_reboot = 'no'` parameter disables automatic reboot. Schedules
in these examples remain `DISABLED`.

## EXAMPLES

### Example 1: Build from scratch and run the complete disabled schedule CRUD flow

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

$beforeIds = @(Get-Action1AutomationSchedules -ErrorAction Stop |
    Select-Object -ExpandProperty id)
$configurationId = [string]$definition.configuration.id
$createResponse = New-Action1AutomationSchedule `
    -AutomationScheduleDefinition $definition -Force -ErrorAction Stop

$created = $null
for ($attempt = 1; $attempt -le 6; $attempt++) {
    $schedules = @(Get-Action1AutomationSchedules -ErrorAction Stop)
    $matches = @($schedules | Where-Object {
        $_.id -notin $beforeIds -and $_.configuration.name -ceq $scheduleName
    })
    if ($matches.Count -gt 1) { throw 'More than one fresh schedule matches this name.' }
    if ($matches.Count -eq 1) { $created = $matches[0]; break }
    if ($attempt -lt 6) { Start-Sleep -Seconds 2 }
}
if ($null -eq $created) { throw 'The new schedule did not appear before the timeout.' }
$scheduleId = [string]$created.id
$details = Get-Action1AutomationSchedule -AutomationInstanceId $scheduleId -ErrorAction Stop
if ($null -eq $details -or $details.id -ne $scheduleId -or
    $details.configuration.id -ne $configurationId -or
    $details.configuration.name -cne $scheduleName) {
    throw 'Created schedule read-back failed.'
}

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

# Remove only the schedule discovered for this generated name and absent from the baseline.
$owned = Get-Action1AutomationSchedule -AutomationInstanceId $scheduleId -ErrorAction Stop
if ($null -eq $owned -or $owned.id -ne $scheduleId -or $scheduleId -in $beforeIds -or
    -not $owned.configuration.name.StartsWith($scheduleName, [StringComparison]::Ordinal)) {
    throw 'Refusing removal: the schedule does not belong to this example run.'
}
$removeResponse = Remove-Action1AutomationSchedule `
    -AutomationInstanceId $scheduleId -Force -ErrorAction Stop
if ($removeResponse.Status -ne 'Removed') { throw 'The schedule was not removed.' }

$remaining = @()
for ($attempt = 1; $attempt -le 6; $attempt++) {
    $remaining = @(Get-Action1AutomationSchedules -ErrorAction Stop |
        Where-Object { $_.id -eq $scheduleId })
    if ($remaining.Count -eq 0) { break }
    if ($attempt -lt 6) { Start-Sleep -Seconds 2 }
}
if ($remaining.Count -gt 0) { throw 'The removed schedule is still listed.' }
try {
    $deleted = Get-Action1AutomationSchedule `
        -AutomationInstanceId $scheduleId -ErrorAction Stop
    throw 'Expected HTTP 400 after schedule removal.'
}
catch {
    $notFoundPattern = [regex]::Escape("Automation with id=$scheduleId not found")
    if (($_.FullyQualifiedErrorId -split ',')[0] -ne 'Action1ApiRequestHttp400' -or
        $_.Exception.Message -notmatch $notFoundPattern) {
        throw
    }
    Write-Verbose "Expected HTTP 400: schedule [$scheduleId] was not found."
}
```

Creates a schedule, discovers its resource ID from the saved list and generated name,
and reads it directly. The update is also built from scratch while retaining the
stored configuration GUID. Both list and direct read verify the changed name; the
direct read also checks retry minutes, disabled state, timezone, and configuration ID.
Cleanup verifies ownership, removes the schedule, confirms list absence, and accepts
only the matching HTTP 400 not-found error from the direct getter.

### Example 2: Clone an existing schedule and run the same CRUD flow

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

$beforeIds = @(Get-Action1AutomationSchedules -ErrorAction Stop |
    Select-Object -ExpandProperty id)
$configurationId = [string]$definition.configuration.id
$createResponse = New-Action1AutomationSchedule `
    -AutomationScheduleDefinition $definition -Force -ErrorAction Stop

$created = $null
for ($attempt = 1; $attempt -le 6; $attempt++) {
    $schedules = @(Get-Action1AutomationSchedules -ErrorAction Stop)
    $matches = @($schedules | Where-Object {
        $_.id -notin $beforeIds -and $_.configuration.name -ceq $scheduleName
    })
    if ($matches.Count -gt 1) { throw 'More than one fresh schedule matches this name.' }
    if ($matches.Count -eq 1) { $created = $matches[0]; break }
    if ($attempt -lt 6) { Start-Sleep -Seconds 2 }
}
if ($null -eq $created) { throw 'The new schedule did not appear before the timeout.' }
$scheduleId = [string]$created.id
$details = Get-Action1AutomationSchedule -AutomationInstanceId $scheduleId -ErrorAction Stop
if ($null -eq $details -or $details.id -ne $scheduleId -or
    $details.configuration.id -ne $configurationId -or
    $details.configuration.name -cne $scheduleName) {
    throw 'Created schedule read-back failed.'
}

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

# Remove only the schedule discovered for this generated name and absent from the baseline.
$owned = Get-Action1AutomationSchedule -AutomationInstanceId $scheduleId -ErrorAction Stop
if ($null -eq $owned -or $owned.id -ne $scheduleId -or $scheduleId -in $beforeIds -or
    -not $owned.configuration.name.StartsWith($scheduleName, [StringComparison]::Ordinal)) {
    throw 'Refusing removal: the schedule does not belong to this example run.'
}
$removeResponse = Remove-Action1AutomationSchedule `
    -AutomationInstanceId $scheduleId -Force -ErrorAction Stop
if ($removeResponse.Status -ne 'Removed') { throw 'The schedule was not removed.' }

$remaining = @()
for ($attempt = 1; $attempt -le 6; $attempt++) {
    $remaining = @(Get-Action1AutomationSchedules -ErrorAction Stop |
        Where-Object { $_.id -eq $scheduleId })
    if ($remaining.Count -eq 0) { break }
    if ($attempt -lt 6) { Start-Sleep -Seconds 2 }
}
if ($remaining.Count -gt 0) { throw 'The removed schedule is still listed.' }
try {
    $deleted = Get-Action1AutomationSchedule `
        -AutomationInstanceId $scheduleId -ErrorAction Stop
    throw 'Expected HTTP 400 after schedule removal.'
}
catch {
    $notFoundPattern = [regex]::Escape("Automation with id=$scheduleId not found")
    if (($_.FullyQualifiedErrorId -split ',')[0] -ne 'Action1ApiRequestHttp400' -or
        $_.Exception.Message -notmatch $notFoundPattern) {
        throw
    }
    Write-Verbose "Expected HTTP 400: schedule [$scheduleId] was not found."
}
```

The source must include usable actions and targets; otherwise provide explicit
replacements as shown by **New-Action1AutomationScheduleDefinition**. Creating the
clone uses a new configuration GUID. Updating the clone preserves that GUID through
ExistingSchedule. Every mutation after create uses the discovered clone ID; the
source resource is retained. Clone targets and actions are not executed because
the new schedule stays disabled.

### Example 3: Preview creation of an already built schedule definition

```powershell
New-Action1AutomationSchedule -AutomationScheduleDefinition $definition -Force -WhatIf
```

Use a definition built by Example 1 or 2 before submission. WhatIf skips signing
and the POST request. Earlier getters used to construct that definition still run.

## PARAMETERS

### -AutomationScheduleDefinition

Specifies the automation schedule definition to create as a PowerShell object,
such as a hashtable or an object returned by **ConvertFrom-Json**. The value must
not be null or empty.

The object supplies the Action1 request body and is signed in place for API 4.0.
Use the definition schema expected by the configured API version. API 3.0 keeps
the actions and schedule settings at the root; API 4.0 places them inside
`configuration`. The body version and organization must match the request URI.
Configure session signing credentials with **Set-Action1Sign** for API 4.0.

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
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

Shows what would happen if the cmdlet runs without sending the POST request.

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

Returns the Action1 API response for the created automation schedule without
changing its properties.

## NOTES

Requires the default Action1 organization to be configured with
**Set-Action1DefaultOrg**. The request URL uses that default organization.

The command reports an error if the request helper returns a null response.

## RELATED LINKS

[New-Action1AutomationScheduleDefinition](New-Action1AutomationScheduleDefinition.md)
[Get-Action1AutomationSchedules](Get-Action1AutomationSchedules.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
[Set-Action1Sign](../configuration/Set-Action1Sign.md)
[New-Action1AutomationActionFilter](New-Action1AutomationActionFilter.md)
[New-Action1AutomationAction](New-Action1AutomationAction.md)
[New-Action1AutomationTarget](New-Action1AutomationTarget.md)
[Get-Action1AutomationSchedule](Get-Action1AutomationSchedule.md)
[Update-Action1AutomationSchedule](Update-Action1AutomationSchedule.md)
[Remove-Action1AutomationSchedule](Remove-Action1AutomationSchedule.md)
[Get-Action1Endpoints](../endpoint/Get-Action1Endpoints.md)
[Get-Action1EndpointGroups](../endpointgroup/Get-Action1EndpointGroups.md)
