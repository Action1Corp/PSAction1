---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1EndpointGroup

## SYNOPSIS

Gets one endpoint group by endpoint group ID or endpoint group name.

## SYNTAX

### ByGroupId (Default)
```
Get-Action1EndpointGroup [-GroupId] <String> [<CommonParameters>]
```

### ByGroupName
```
Get-Action1EndpointGroup -GroupName <String> [<CommonParameters>]
```

## DESCRIPTION

Gets detailed information about a specific endpoint group by using the Action1
endpoint groups API.

The command uses the module default organization configured by
**Set-Action1DefaultOrg**.

The command accepts an endpoint group ID or an endpoint group name. When
**-GroupName** is used, the command resolves the name by searching endpoint
groups in the current organization and then calls the single endpoint group API
path with the resolved ID.

## EXAMPLES

### Example 1: Get an endpoint group by ID

```powershell
Get-Action1EndpointGroup -GroupId 'Service_1696554367754'
```

Gets details for the specified endpoint group in the current Action1
organization.

### Example 2: Get an endpoint group by name

```powershell
Get-Action1EndpointGroup -GroupName 'Service'
```

Resolves the endpoint group named Service and gets that endpoint group.

### Example 3: Display endpoint group details

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
Parameter Sets: ByGroupId
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -GroupName

Specifies the name of the endpoint group to retrieve.

The command resolves the name by calling `Resolve-Action1EndpointGroupByName`.
If the name is not found or is not unique, the command writes a terminating
error.

```yaml
Type: String
Parameter Sets: ByGroupName
Aliases:

Required: True
Position: Named
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

After resolving the endpoint group identity, this command calls the single
endpoint group API path without pagination.

## RELATED LINKS

[Get-Action1EndpointGroups](Get-Action1EndpointGroups.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
