---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Update-Action1Enterprise

## SYNOPSIS

Updates the name or description of the current Action1 enterprise.

## SYNTAX

```
Update-Action1Enterprise [-Name <String>] [-Description <String>] [-Force] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

## DESCRIPTION

`Update-Action1Enterprise` calls the Action1 enterprise API and updates settings
for the current enterprise. Action1 allows access only to the current enterprise.

Specify at least one value to update: **-Name** or **-Description**. You can
specify both parameters in the same command.

The PATCH request body includes only the update parameters that you specify.
For example, when you specify only **-Name**, the request body contains only
**name**. When you specify both **-Name** and **-Description**, the request body
contains both **name** and **description**.

This command supports PowerShell confirmation. Use **-WhatIf** to preview the
update without sending the PATCH request. Use **-Confirm** to prompt before
sending the PATCH request. Use **-Force** to bypass confirmation prompts.

The requested PATCH endpoint is `/enterprise`.

## EXAMPLES

### Example 1: Update the enterprise name

```powershell
Update-Action1Enterprise -Name 'My Enterprise'
```

Updates the name of the current Action1 enterprise.

### Example 2: Update the enterprise description

```powershell
Update-Action1Enterprise -Description 'Description for my enterprise'
```

Updates the description of the current Action1 enterprise.

### Example 3: Update the enterprise name and description

```powershell
Update-Action1Enterprise `
    -Name 'My Enterprise' `
    -Description 'Description for my enterprise'
```

Updates both the name and description of the current Action1 enterprise.

### Example 4: Preview an enterprise update

```powershell
Update-Action1Enterprise `
    -Name 'My Enterprise' `
    -Description 'Description for my enterprise' `
    -WhatIf
```

Shows what would be updated without sending the PATCH request.

### Example 5: Update enterprise settings without prompting

```powershell
Update-Action1Enterprise `
    -Description 'Description for my enterprise' `
    -Force
```

Updates the enterprise description without prompting for confirmation.

## PARAMETERS

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

### -Description

Specifies the new enterprise description.

Specify **-Description**, **-Name**, or both. The command writes an error when
neither parameter is specified.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Force

Bypasses confirmation prompts. **-WhatIf** is still honored when it is specified.

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

### -Name

Specifies the new enterprise name.

Specify **-Name**, **-Description**, or both. The command writes an error when
neither parameter is specified.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
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

### None

This command does not accept pipeline input.

## OUTPUTS

### System.Object

Returns the updated enterprise object returned by Action1.

## NOTES

Requires permission to manage enterprise settings in Action1.

## RELATED LINKS

[Get-Action1Enterprise](Get-Action1Enterprise.md)
