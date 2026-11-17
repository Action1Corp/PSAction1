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
request definition expected by the Action1 API, including the `endpoints` and
`configuration` properties. Build the definition separately before calling this
command. To use a JSON string or file, first convert it to an object with
**ConvertFrom-Json**.

The command passes the supplied definition directly to the shared Action1 request
helper, which serializes it as JSON. It does not build the definition, merge in
existing schedule values, or validate the definition schema locally. API
validation errors are reported by the request helper.

Use **-WhatIf** to preview the operation without sending the PATCH request. Use
**-Confirm** to request confirmation or **-Force** to suppress confirmation prompts
while still honoring **-WhatIf**.

## EXAMPLES

### Example 1: Update an automation schedule from a prepared definition

```powershell
Update-Action1AutomationSchedule `
    -AutomationInstanceId '11111111-1111-1111-1111-111111111111' `
    -AutomationScheduleDefinition $automationScheduleDefinition
```

Updates the specified schedule in the current organization using a definition
object built separately.

### Example 2: Update an automation schedule from a JSON file

```powershell
$automationScheduleDefinition = Get-Content `
    -LiteralPath '.\AutomationScheduleDefinition.json' `
    -Raw | ConvertFrom-Json

Update-Action1AutomationSchedule `
    -AutomationInstanceId '11111111-1111-1111-1111-111111111111' `
    -AutomationScheduleDefinition $automationScheduleDefinition `
    -Force
```

Reads a prepared JSON request definition and updates the automation schedule
without prompting for confirmation.

### Example 3: Preview an automation schedule update

```powershell
Update-Action1AutomationSchedule `
    -AutomationInstanceId '11111111-1111-1111-1111-111111111111' `
    -AutomationScheduleDefinition $automationScheduleDefinition `
    -Force `
    -WhatIf
```

Shows the update operation without sending an API request, even when **-Force**
is specified.

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

The object is passed directly to the Action1 request helper as the PATCH body.
Use the definition schema expected by the API, including `endpoints` and
`configuration` with the schedule's actions and settings.

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

[Get-Action1AutomationSchedules](Get-Action1AutomationSchedules.md)
[New-Action1AutomationSchedule](New-Action1AutomationSchedule.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
