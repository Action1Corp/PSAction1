---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Remove-Action1AutomationSchedule

## SYNOPSIS

Deletes an automation schedule in the current Action1 organization.

## SYNTAX

```
Remove-Action1AutomationSchedule [-AutomationInstanceId] <String> [-Force] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

## DESCRIPTION

Deletes an automation schedule by sending a DELETE request to
`/automations/schedules/{orgId}/{automationId}` using the module default
organization configured by **Set-Action1DefaultOrg**. The
**AutomationInstanceId** parameter supplies the `{automationId}` path segment
and identifies the schedule to delete.

The command uses **ConfirmImpact = High** and prompts for confirmation with the
default confirmation preference. Use **-WhatIf** to preview the operation without
initializing the default organization or sending the DELETE request. Use
**-Force** or **-Confirm:$false** to suppress confirmation prompts. **-Force**
still honors **-WhatIf**.

## EXAMPLES

### Example 1: Delete an automation schedule

```powershell
Remove-Action1AutomationSchedule `
    -AutomationInstanceId '11111111-1111-1111-1111-111111111111'
```

Prompts for confirmation and deletes the specified schedule in the current
organization if confirmed.

### Example 2: Delete an automation schedule without prompting

```powershell
Remove-Action1AutomationSchedule `
    -AutomationInstanceId '11111111-1111-1111-1111-111111111111' `
    -Force
```

Deletes the specified schedule without prompting for confirmation.

### Example 3: Preview an automation schedule deletion

```powershell
Remove-Action1AutomationSchedule `
    -AutomationInstanceId '11111111-1111-1111-1111-111111111111' `
    -Force `
    -WhatIf
```

Shows the deletion operation and returns a result with **Status** set to
**Skipped**, without sending an API request, even when **-Force** is specified.

## PARAMETERS

### -AutomationInstanceId

Specifies the ID of the automation schedule to delete. Despite the parameter
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

### -Confirm

Prompts you for confirmation before deleting the automation schedule.

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

Shows what would happen if the cmdlet runs without sending the DELETE request.

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

### System.Management.Automation.PSCustomObject

Returns a result containing **AutomationInstanceId**, **Status**, and **Response**.
**Status** is **Removed** when the request succeeds, **Skipped** when
**ShouldProcess** declines the operation, or **Failed** when the request helper
returns null. **Response** contains the raw API response content on success and
is null for skipped or failed operations. Successful empty response content is
returned as an empty string in **Response**.

## NOTES

Requires the default Action1 organization to be configured with
**Set-Action1DefaultOrg**. The request URL uses that default organization.

The command reports an error if the request helper returns a null response.
With **-ErrorAction Stop**, the error terminates the command before a failed
result can be returned.

## RELATED LINKS

[Get-Action1AutomationSchedules](Get-Action1AutomationSchedules.md)
[New-Action1AutomationSchedule](New-Action1AutomationSchedule.md)
[Update-Action1AutomationSchedule](Update-Action1AutomationSchedule.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
