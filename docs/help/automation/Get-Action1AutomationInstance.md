---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1AutomationInstance

## SYNOPSIS

Gets one automation instance by ID for the current Action1 organization.

## SYNTAX

```
Get-Action1AutomationInstance [-AutomationInstanceId] <String> [<CommonParameters>]
```

## DESCRIPTION

Gets an automation instance from
`/automations/instances/{orgId}/{automationInstanceId}` by using the module
default organization configured by **Set-Action1DefaultOrg**.

The command calls the shared API request helper without pagination and returns
the response object without changing its properties.

## EXAMPLES

### Example 1: Get an automation instance by ID

```powershell
Get-Action1AutomationInstance -AutomationInstanceId '11111111-1111-1111-1111-111111111111'
```

Gets the specified automation instance in the current organization.

### Example 2: Display automation instance details

```powershell
Get-Action1AutomationInstance '11111111-1111-1111-1111-111111111111' |
    Format-List
```

Passes the automation instance ID positionally and displays all returned fields.

## PARAMETERS

### -AutomationInstanceId

Specifies the ID of the automation instance to retrieve. The value cannot be
null or empty.

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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe input to this command.

## OUTPUTS

### System.Object

Returns the automation instance object returned by Action1.

## NOTES

Requires the default Action1 organization to be configured with
**Set-Action1DefaultOrg**.

The command uses **Invoke-Action1ApiRequest** to send a single GET request.

## RELATED LINKS

[Get-Action1AutomationInstances](Get-Action1AutomationInstances.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
