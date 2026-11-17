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
definition expected by the Action1 API, including the `endpoints` and
`configuration` properties. Build the definition separately before calling this
command. To use a JSON string or file, first convert it to an object with
**ConvertFrom-Json**.

The command passes the definition directly to the shared Action1 request helper,
which serializes it as JSON. The command does not validate the definition schema
locally; API validation errors are reported by the request helper.

The command prompts for confirmation before starting an automation.
Use **-WhatIf** to preview the operation without sending the POST request. Use
**-Force** to suppress confirmation prompts while still honoring **-WhatIf**.

## EXAMPLES

### Example 1: Start an automation from a prepared definition

```powershell
Start-Action1Automation -AutomationDefinition $automationDefinition
```

Starts an automation in the current organization using a definition object built
separately and prompts for confirmation.

### Example 2: Start an automation from a JSON file

```powershell
$automationDefinition = Get-Content `
    -LiteralPath '.\AutomationDefinition.json' `
    -Raw | ConvertFrom-Json

$automationInstance = Start-Action1Automation `
    -AutomationDefinition $automationDefinition `
    -Force
```

Reads a prepared JSON request definition, starts the automation without prompting
for confirmation, and stores the returned automation instance.

### Example 3: Preview starting an automation

```powershell
Start-Action1Automation -AutomationDefinition $automationDefinition -WhatIf
```

Shows the start operation without sending an API request.

## PARAMETERS

### -AutomationDefinition

Specifies the automation definition to start as a PowerShell object, such as a
hashtable or an object returned by **ConvertFrom-Json**. The value must not be
null or empty.

The object is passed directly to the Action1 request helper as the request body.
Use the definition schema expected by the API, including `endpoints` with target
IDs and types, and `configuration` with the automation's actions and settings.

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

Returns the Action1 API response for the started automation instance without
changing its properties, including `id`, `type`, `self`, `configuration`,
`endpoints`, and `signatures` when returned by the API.

## NOTES

Requires the default Action1 organization to be configured with
**Set-Action1DefaultOrg**. The request URL uses that default organization.

The command reports an error if the request helper returns a null response.

## RELATED LINKS

[Get-Action1AutomationInstances](Get-Action1AutomationInstances.md)
[Get-Action1AutomationInstance](Get-Action1AutomationInstance.md)
[New-Action1AutomationSchedule](New-Action1AutomationSchedule.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
