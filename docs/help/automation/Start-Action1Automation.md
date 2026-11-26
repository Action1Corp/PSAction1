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

Returns the Action1 API response for the started automation instance without
changing its properties, including `id`, `type`, `self`, `configuration`,
`endpoints`, and `signatures` when returned by the API.

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
