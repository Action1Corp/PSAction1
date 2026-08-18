---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Remove-Action1EndpointGroup

## SYNOPSIS

Removes an endpoint group from the current Action1 organization.

## SYNTAX

### ByGroupId (Default)
```
Remove-Action1EndpointGroup [-GroupId] <String> [-Force] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

### ByGroupName
```
Remove-Action1EndpointGroup -GroupName <String> [-Force] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

## DESCRIPTION

Removes an endpoint group from the current Action1 organization by calling the
Action1 endpoint group API.

The command accepts an endpoint group ID or an endpoint group name. When
**-GroupName** is used, the command resolves the name by searching endpoint
groups in the current organization and then calls the endpoint group API path
with the resolved ID.

Use **-WhatIf** to preview the operation. Use **-Force** to bypass confirmation
prompts.

The command uses the module default organization configured by
**Set-Action1DefaultOrg**.

## EXAMPLES

### Example 1: Remove an endpoint group by ID

```powershell
Remove-Action1EndpointGroup -GroupId 'Win10_1765215211802'
```

Removes the specified endpoint group from the current Action1 organization.

### Example 2: Remove an endpoint group by name

```powershell
Remove-Action1EndpointGroup -GroupName 'Windows 10'
```

Resolves the endpoint group named Windows 10 and removes it.

### Example 3: Remove an endpoint group without prompting

```powershell
Remove-Action1EndpointGroup `
    -GroupId 'Win10_1765215211802' `
    -Force
```

Removes the endpoint group without prompting for confirmation.

### Example 4: Preview endpoint group removal

```powershell
Remove-Action1EndpointGroup `
    -GroupName 'Windows 10' `
    -WhatIf
```

Shows the remove operation without sending the DELETE request.

## PARAMETERS

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

### -GroupId

Specifies the ID of the endpoint group to remove.

Endpoint group IDs are opaque strings, not GUIDs.

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

Specifies the name of the endpoint group to remove.

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

### -WhatIf
Shows what would happen if the cmdlet runs. The cmdlet is not run.

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

Returns an object with `GroupId`, `GroupName`, `Status`, and `Response`.

## NOTES

Requires the default Action1 organization to be configured with
**Set-Action1DefaultOrg**.

The command sends a DELETE request to the endpoint group API path:
`/endpoints/groups/:orgId/:groupId`.

## RELATED LINKS

[Get-Action1EndpointGroup](Get-Action1EndpointGroup.md)
[Get-Action1EndpointGroups](Get-Action1EndpointGroups.md)
[New-Action1EndpointGroup](New-Action1EndpointGroup.md)
[Update-Action1EndpointGroup](Update-Action1EndpointGroup.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
