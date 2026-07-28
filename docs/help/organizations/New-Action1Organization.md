---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# New-Action1Organization

## SYNOPSIS

Creates an Action1 organization.

## SYNTAX

```
New-Action1Organization [-Name] <String> [-Description <String>] [-WhatIf]
 [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

`New-Action1Organization` calls the Action1 organizations API and creates a new
organization with the specified name and description.

The **-Description** parameter is optional and defaults to an empty string. The
API body always includes the **description** property.

This command supports PowerShell confirmation. Use **-WhatIf** to preview the
operation without sending the POST request. Use **-Confirm** to prompt for
confirmation before sending the POST request.

## EXAMPLES

### Example 1: Create an organization

```powershell
New-Action1Organization `
    -Name 'My Organization' `
    -Description 'This is my organization description example text'
```

Creates an organization and returns the organization object returned by Action1.

### Example 2: Preview organization creation

```powershell
New-Action1Organization `
    -Name 'My Organization' `
    -Description 'This is my organization description example text' `
    -WhatIf
```

Shows what would be created without sending the POST request.

### Example 3: Create an organization with the default empty description

```powershell
New-Action1Organization -Name 'My Organization'
```

Creates an organization and sends an empty string in the **description** field.

## PARAMETERS

### -Description

Specifies the organization description.

This parameter is optional and defaults to an empty string. When omitted, the
command still sends the **description** field in the request body.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: ''
Accept pipeline input: False
Accept wildcard characters: False
```

### -Name

Specifies the organization name.

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

Prompts you for confirmation before running the command.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIf

Shows what would happen if the command runs. The command is not run.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: wi

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### System.Object

Returns the organization object returned by Action1.

## NOTES

Requires permission to manage organizations in Action1.

## RELATED LINKS

[Get-Action1Organization](Get-Action1Organization.md)
[Get-Action1Organizations](../configuration/Get-Action1Organizations.md)
[Update-Action1Organization](Update-Action1Organization.md)
[Remove-Action1Organization](Remove-Action1Organization.md)
