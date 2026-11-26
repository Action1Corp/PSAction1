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

## EXAMPLES

### Example 1: Create an automation schedule from a prepared definition

```powershell
New-Action1AutomationSchedule `
    -AutomationScheduleDefinition $automationScheduleDefinition
```

Creates a schedule in the current organization using a definition object built
separately and prompts for confirmation.

### Example 2: Create an automation schedule from a JSON file

```powershell
$automationScheduleDefinition = Get-Content `
    -LiteralPath '.\AutomationScheduleDefinition.json' `
    -Raw | ConvertFrom-Json

New-Action1AutomationSchedule `
    -AutomationScheduleDefinition $automationScheduleDefinition `
    -Force
```

Reads a prepared JSON request definition and creates the automation schedule
without prompting for confirmation.

### Example 3: Preview automation schedule creation

```powershell
New-Action1AutomationSchedule `
    -AutomationScheduleDefinition $automationScheduleDefinition `
    -WhatIf
```

Shows the create operation without sending an API request.

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
