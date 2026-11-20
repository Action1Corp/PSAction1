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

## EXAMPLES

### Example 1: Stop an automation instance

```powershell
Stop-Action1Automation -AutomationInstanceId '11111111-1111-1111-1111-111111111111'
```

Stops the specified automation instance in the current organization after
prompting for confirmation.

### Example 2: Stop an automation instance without confirmation

```powershell
$response = Stop-Action1Automation `
    -AutomationInstanceId '11111111-1111-1111-1111-111111111111' `
    -Force
```

Stops the specified automation instance without prompting and stores the API
response in **$response**.

### Example 3: Preview stopping an automation instance

```powershell
Stop-Action1Automation `
    -AutomationInstanceId '11111111-1111-1111-1111-111111111111' `
    -Force `
    -WhatIf
```

Shows the stop operation without sending an API request, even when **-Force**
is specified.

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
