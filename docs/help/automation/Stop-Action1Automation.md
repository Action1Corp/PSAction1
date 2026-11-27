---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Stop-Action1Automation

## SYNOPSIS

Stops an automation instance in the current Action1 organization.

## SYNTAX

```
Stop-Action1Automation [-AutomationInstanceId] <String> [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

Stops an automation instance by sending a POST request without a body to
`/automations/instances/{orgId}/{instanceId}/stop` using the module default
organization configured by **Set-Action1DefaultOrg**. The
**AutomationInstanceId** parameter supplies the `{instanceId}` path segment.

The command prompts for confirmation before stopping the automation instance.
Use **-WhatIf** to preview the operation without sending the POST request. Use
**-Force** to suppress confirmation prompts while still honoring **-WhatIf**.

A definition built from scratch with **New-Action1AutomationDefinition**, or
rebuilt with its ExistingAutomation parameter, follows the same lifecycle:
**Start-Action1Automation** -> find the fresh instance in completed/active lists ->
**Get-Action1AutomationInstance** -> this command. Stop accepts the discovered
instance resource ID, not the definition object, configuration GUID, or schedule
resource ID. It sends no body and does not sign a configuration.

Stopping requests that execution stop. It does not undo completed endpoint
actions, delete the instance from history, or delete/disable a schedule. Use
**Update-Action1AutomationSchedule** to change a schedule definition and
**Remove-Action1AutomationSchedule** to remove a schedule resource.

The API 4.0 examples use an authenticated session with an API 4.0 region,
a default test organization, and signing credentials configured through
**Set-Action1Credentials**, **Set-Action1Region**, **Set-Action1DefaultOrg**, and
**Set-Action1Sign**. The definition's API version and organization must match
the submission URI. The security-update action can install matching updates when
started; its `auto_reboot = 'no'` parameter disables automatic reboot. Schedules
in these examples remain `DISABLED`.

## EXAMPLES

### Example 1: Stop an instance selected from the active list

```powershell
$instances = @(Get-Action1AutomationInstances -NotCompleted -ErrorAction Stop)
$instances | Select-Object id, name, status
$instanceId = Read-Host 'Test instance ID to stop'
$selected = @($instances | Where-Object { $_.id -eq $instanceId })
if ($selected.Count -ne 1) { throw 'Select exactly one returned instance ID.' }
$details = Get-Action1AutomationInstance -AutomationInstanceId $instanceId -ErrorAction Stop
if ($null -eq $details -or $details.id -ne $instanceId) { throw 'Instance read-back failed.' }
$response = Stop-Action1Automation -AutomationInstanceId $instanceId -ErrorAction Stop
```

Lists active executions, reads the explicitly selected instance, and prompts before
stopping it. Supply the instance resource ID, not a definition configuration GUID
or schedule resource ID. This command sends no definition body and requires no signing.

### Example 2: Start and stop a definition built from scratch or from an existing instance

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

First build `$definition` and its generated `$runName` using Example 1 or 2 of
**New-Action1AutomationDefinition**. This continuation is the same for both builder
paths: capture the baseline, start, discover the fresh instance ID, read it, and stop.
The combined list includes quickly completed executions. Stopping cannot undo actions
that have already completed; the instance remains available in execution history.

### Example 3: Preview stopping an instance and read its history

```powershell
# $instanceId is the ID selected or discovered above.
Stop-Action1Automation -AutomationInstanceId $instanceId -Force -WhatIf
$history = Get-Action1AutomationInstance -AutomationInstanceId $instanceId -ErrorAction Stop
```

WhatIf skips the stop request even with Force. The separate GET still runs.
Stop does not delete the instance, remove a schedule, or update a definition.

## PARAMETERS

### -AutomationInstanceId

Specifies the ID of the automation instance to stop. The value cannot be null
or empty.

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

Returns the Action1 API response unchanged. The expected success response
contains `id` (`"0"`), `type` (`"Success"`), `status` (`200`),
`developer_message` (`"Success"`), and `user_message` (`"Success"`).

## NOTES

Requires the default Action1 organization to be configured with
**Set-Action1DefaultOrg**. The request URL uses that default organization.

The command reports an error if the request helper returns a null response.

## RELATED LINKS

[Start-Action1Automation](Start-Action1Automation.md)
[Get-Action1AutomationInstances](Get-Action1AutomationInstances.md)
[Get-Action1AutomationInstance](Get-Action1AutomationInstance.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
[New-Action1AutomationDefinition](New-Action1AutomationDefinition.md)
[Update-Action1AutomationSchedule](Update-Action1AutomationSchedule.md)
[Remove-Action1AutomationSchedule](Remove-Action1AutomationSchedule.md)
