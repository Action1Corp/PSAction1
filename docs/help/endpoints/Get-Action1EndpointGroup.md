---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1EndpointGroup

## SYNOPSIS

Gets one endpoint group from the current Action1 organization.

## SYNTAX

```
Get-Action1EndpointGroup [-GroupId] <String> [<CommonParameters>]
```

## DESCRIPTION

Gets detailed information about a specific endpoint group by using the Action1
endpoint groups API.

The command uses the module default organization configured by
**Set-Action1DefaultOrg**.

## EXAMPLES

### Example 1: Get an endpoint group by ID

```powershell
Get-Action1EndpointGroup -GroupId 'Service_1696554367754'
```

Gets details for the specified endpoint group in the current Action1
organization.

### Example 2: Display endpoint group details

```powershell
Get-Action1EndpointGroup -GroupId 'Service_1696554367754' |
    Format-List
```

Gets the endpoint group and displays all returned fields.

## PARAMETERS

### -GroupId

Specifies the ID of the endpoint group to retrieve.

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

This cmdlet supports the common parameters: -Debug, -ErrorAction,
-ErrorVariable, -InformationAction, -InformationVariable, -OutVariable,
-OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable.
For more information, see
[about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe input to this command.

## OUTPUTS

### System.Object

Returns the endpoint group object returned by Action1.

## NOTES

Requires the default Action1 organization to be configured with
**Set-Action1DefaultOrg**.

This command calls the single endpoint group API path and does not use
pagination.

## RELATED LINKS

[Get-Action1EndpointGroups](Get-Action1EndpointGroups.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)

