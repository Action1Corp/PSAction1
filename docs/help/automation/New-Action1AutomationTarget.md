---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# New-Action1AutomationTarget

## SYNOPSIS

Builds an automation endpoint or endpoint-group reference locally.

## SYNTAX

```powershell
New-Action1AutomationTarget -Id <String> -Type <String> [<CommonParameters>]
```

## DESCRIPTION

Creates an object with `id` and `type` for an automation's `endpoints` array.
No API request is made. Individual endpoint IDs must be GUIDs. Endpoint-group IDs
can be nonempty strings, including the explicit all-endpoints group ID `ALL`.
The returned type is normalized to `Endpoint` or `EndpointGroup`.

## EXAMPLES

### Example 1: Create a group target

```powershell
$target = New-Action1AutomationTarget -Id 'maintenance_group' -Type EndpointGroup
```

Builds a group reference for a definition builder.

### Example 2: Select all endpoints explicitly

```powershell
$allEndpoints = New-Action1AutomationTarget -Id ALL -Type EndpointGroup
```

Builds an explicit all-endpoints reference. Builders never select ALL automatically.

## PARAMETERS

### -Id

The endpoint GUID or endpoint-group ID. Null, empty, and whitespace values are rejected.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Type

The target type. Accepted values: Endpoint, EndpointGroup.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
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

Returns one PSCustomObject containing `id` and `type`.

## NOTES

This command constructs a reference; it does not verify that the target exists.
It does not require credentials, a region, or a default organization.

## RELATED LINKS

[New-Action1AutomationDefinition](New-Action1AutomationDefinition.md)
[New-Action1AutomationScheduleDefinition](New-Action1AutomationScheduleDefinition.md)
