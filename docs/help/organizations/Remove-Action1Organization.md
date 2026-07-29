---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Remove-Action1Organization

## SYNOPSIS

Removes one Action1 organization.

## SYNTAX

### ByOrgId (Default)
```
Remove-Action1Organization [-OrgID] <String> [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### ByOrganizationObject
```
Remove-Action1Organization -OrganizationObject <Object> [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

`Remove-Action1Organization` calls the Action1 organizations API and removes an
organization by ID.

The command accepts an organization ID in standard GUID format or an
organization object with an **id**, **OrgID**, or **Org_ID** property. When the
organization object includes **name**, **OrgName**, or **Org_Name**, the name is
included in confirmation, debug, and error information.

The API fails when the specified organization still contains endpoints or when
it is the last organization in the enterprise.

This command supports PowerShell confirmation. Use **-WhatIf** to preview the
delete operation without sending the DELETE request. Use **-Confirm** to prompt
before sending the DELETE request. Use **-Force** to bypass confirmation prompts.

## EXAMPLES

### Example 1: Remove an organization

```powershell
Remove-Action1Organization -OrgID '88c8b425-871e-4ff6-9afc-00df8592c6db'
```

Prompts for confirmation and removes the specified organization.

### Example 2: Preview organization removal

```powershell
Remove-Action1Organization `
    -OrgID '88c8b425-871e-4ff6-9afc-00df8592c6db' `
    -WhatIf
```

Shows what would be removed without sending the DELETE request.

### Example 3: Remove an organization from the pipeline

```powershell
Get-Action1Organizations |
    Where-Object Org_Name -eq 'Test Lab' |
    Remove-Action1Organization -Force
```

Removes an organization by using the **Org_ID** property from the piped object.

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

### -OrgID

Specifies the organization ID.

The organization ID must use the standard GUID format, such as
`88c8b425-871e-4ff6-9afc-00df8592c6db`.

```yaml
Type: String
Parameter Sets: ByOrgId
Aliases: Org_ID

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OrganizationObject

Specifies an organization object. The object must include an **id** or
**OrgID** or **Org_ID** property.

```yaml
Type: Object
Parameter Sets: ByOrganizationObject
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByValue)
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

### System.Object

You can pipe organization objects with an **id**, **OrgID**, or **Org_ID**
property to this command.

## OUTPUTS

### PSCustomObject

Returns an object containing **Org_ID**, **Org_Name**, **Status**, and
**Response**.

## NOTES

Requires permission to manage organizations in Action1.

## RELATED LINKS

[Get-Action1Organization](Get-Action1Organization.md)
[Get-Action1Organizations](../configuration/Get-Action1Organizations.md)
[New-Action1Organization](New-Action1Organization.md)
[Update-Action1Organization](Update-Action1Organization.md)
