---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Start-Action1Automation

## SYNOPSIS

Starts an automation in the current Action1 organization.

## SYNTAX

```
Start-Action1Automation [-AutomationDefinition] <Object> [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

Starts an automation by sending a POST request to
`/automations/instances/{orgId}` using the module default organization configured
by **Set-Action1DefaultOrg**.

Supply **AutomationDefinition** as a PowerShell object containing the request
definition expected by the configured API version. API 3.0 uses root-level
`name`, `actions`, `retry_minutes`, and `endpoints`; API 4.0 uses `configuration`
and root-level `endpoints` and signatures. Build the unsigned object with
**New-Action1AutomationDefinition**. For API 4.0, the command signs `configuration`
using the session credentials set by **Set-Action1Sign** and validates the attached
signatures before submission. To use a JSON string or file, first convert it to
an object with **ConvertFrom-Json**.

The configured region's base URI determines the API version. API 3.0 definitions
are passed unchanged to the shared request helper, which serializes them as JSON.
For API 4.0, signing updates the supplied object, generates a configuration GUID
if missing, and replaces existing signatures. Submission requires a nonempty
signature array with valid reference fields and signature fields (`alg`, `iat`,
`kid`, and `value`). This checks signature structure, not cryptographic validity.
Signing failures or invalid signatures prevent the request. Other API validation
errors are reported by the request helper.

The command prompts for confirmation before starting an automation.
Use **-WhatIf** to preview the operation without signing or sending the POST
request. Use **-Force** to suppress confirmation prompts while still honoring
**-WhatIf**.

Build from scratch by resolving real endpoint/group IDs and constructing a
filter, action, target, and **New-Action1AutomationDefinition**. Build from an
existing object by reading one instance and passing it to that builder through
ExistingAutomation. Supply missing action/target collections explicitly and
choose a new configuration GUID and start time for the separate execution.

The unsigned run-now definition is sometimes called an Automation Instance
Definition. An Automation instance itself exists only after submission. Its
execution ID, the API 4.0 configuration GUID, and a schedule resource ID have
different roles. Discover the new instance from completed and active lists using
the baseline IDs and a generated name, read it by that instance ID, then pass the
same ID to **Stop-Action1Automation**. There is no public instance update or delete
command; starting a revised definition creates a separate run.

The API 4.0 examples use an authenticated session with an API 4.0 region,
a default test organization, and signing credentials configured through
**Set-Action1Credentials**, **Set-Action1Region**, **Set-Action1DefaultOrg**, and
**Set-Action1Sign**. The definition's API version and organization must match
the submission URI. The security-update action can install matching updates when
started; its `auto_reboot = 'no'` parameter disables automatic reboot. Schedules
in these examples remain `DISABLED`.

## EXAMPLES

### Example 1: Build from scratch, start, discover, read, and stop one run

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

The builder returns an unsigned run-now definition. Start signs its final API 4.0
configuration and submits POST. Bounded list discovery identifies the new instance
even if it completes quickly. Read-back and stop use the discovered instance ID.
The stop response acknowledges the request; it does not delete execution history.

### Example 2: Build from an existing instance and start a separate run

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

Uses the freshly built `$action` and real `$target` from Example 1 to supplement or
replace source collections. It explicitly replaces configuration identity and start
time. This creates a new execution; it does not update the original instance.
When the source has complete usable collections, Actions and Endpoints can be omitted.

### Example 3: Load a saved definition, rebuild it, and preview submission

```powershell
$saved = Get-Content -LiteralPath '.\AutomationDefinition.json' -Raw | ConvertFrom-Json
$definition = New-Action1AutomationDefinition -ExistingAutomation $saved `
    -Name ('Preview run ' + [guid]::NewGuid().ToString('N')) `
    -ConfigurationId ([guid]::NewGuid().ToString()) `
    -StartTime ([DateTimeOffset]::UtcNow) -ApiVersion '4.0'
Start-Action1Automation -AutomationDefinition $definition -Force -WhatIf
```

The file must contain a complete definition for the configured organization.
The builder returns an unsigned object. WhatIf skips signing and submission,
including when Force is present; it does not skip the earlier file read or builder.

## PARAMETERS

### -AutomationDefinition

Specifies the automation definition to start as a PowerShell object, such as a
hashtable or an object returned by **ConvertFrom-Json**. The value must not be
null or empty.

The object supplies the Action1 request body and is signed in place for API 4.0.
Use the definition schema expected by the configured API version, with explicit
target IDs and types. API 3.0 actions and settings are at the root; API 4.0 places
them inside `configuration`. The body version and organization must match the
request URI. Configure session signing credentials with **Set-Action1Sign** for
API 4.0.

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

Returns the Action1 API submission response without changing its properties.
The response shape depends on the service. Use the completed/active list
difference and detail getter shown above to obtain the new instance resource
ID rather than assuming a response ID is that execution ID.

## NOTES

Requires the default Action1 organization to be configured with
**Set-Action1DefaultOrg**. The request URL uses that default organization.

The command reports an error if the request helper returns a null response.

## RELATED LINKS

[Get-Action1AutomationInstances](Get-Action1AutomationInstances.md)
[New-Action1AutomationDefinition](New-Action1AutomationDefinition.md)
[Get-Action1AutomationInstance](Get-Action1AutomationInstance.md)
[New-Action1AutomationSchedule](New-Action1AutomationSchedule.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
[Set-Action1Sign](../configuration/Set-Action1Sign.md)
[New-Action1AutomationActionFilter](New-Action1AutomationActionFilter.md)
[New-Action1AutomationAction](New-Action1AutomationAction.md)
[New-Action1AutomationTarget](New-Action1AutomationTarget.md)
[Stop-Action1Automation](Stop-Action1Automation.md)
[Get-Action1Endpoints](../endpoint/Get-Action1Endpoints.md)
[Get-Action1EndpointGroups](../endpointgroup/Get-Action1EndpointGroups.md)
