---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Update-Action1Organization

## SYNOPSIS

Updates the name or description of one Action1 organization.

## SYNTAX

### ByOrgId (Default)
```
Update-Action1Organization [-OrgID] <String> [-Name <String>]
 [-Description <String>] [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### ByOrganizationObject
```
Update-Action1Organization -OrganizationObject <Object> [-Name <String>]
 [-Description <String>] [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

`Update-Action1Organization` calls the Action1 organizations API and updates
settings for a specific organization.

The command accepts an organization ID in standard GUID format or an
organization object with an **id**, **OrgID**, or **Org_ID** property. When the
organization object includes **name**, **OrgName**, or **Org_Name**, the name is
included in confirmation, debug, and error information.

Specify at least one value to update: **-Name** or **-Description**. You can
specify both parameters in the same command.

The PATCH request body includes only the update parameters that you specify.
For example, when you specify only **-Name**, the request body contains only
**name**. When you specify both **-Name** and **-Description**, the request body
contains both **name** and **description**.

This command supports PowerShell confirmation. Use **-WhatIf** to preview the
update without sending the PATCH request. Use **-Confirm** to prompt before
sending the PATCH request. Use **-Force** to bypass confirmation prompts.

## EXAMPLES

### Example 1: Update an organization name

```powershell
Update-Action1Organization `
    -OrgID '88c8b425-871e-4ff6-9afc-00df8592c6db' `
    -Name 'My Organization'
```

Updates the name of the specified organization.

### Example 2: Update an organization description

```powershell
Update-Action1Organization `
    -OrgID '88c8b425-871e-4ff6-9afc-00df8592c6db' `
    -Description 'This is my organization description example text'
```

Updates the description of the specified organization.

### Example 3: Update an organization object from the pipeline

```powershell
Get-Action1Organizations |
    Where-Object Org_Name -eq 'Accounting' |
    Update-Action1Organization -Description 'Accounting department'
```

Updates an organization by using the **Org_ID** property from the piped object.

### Example 4: Preview an organization update

```powershell
Update-Action1Organization `
    -OrgID '88c8b425-871e-4ff6-9afc-00df8592c6db' `
    -Name 'My Organization' `
    -WhatIf
```

Shows what would be updated without sending the PATCH request.

### Example 5: Update an organization without prompting

```powershell
Update-Action1Organization `
    -OrgID '88c8b425-871e-4ff6-9afc-00df8592c6db' `
    -Description 'This is my organization description example text' `
    -Force
```

Updates the organization description without prompting for confirmation.

## PARAMETERS

### -Description

Specifies the new organization description.

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

Specifies the new organization name.

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

### System.Object

You can pipe organization objects with an **id**, **OrgID**, or **Org_ID**
property to this command.

## OUTPUTS

### System.Object

Returns the updated organization object returned by Action1.

## NOTES

Requires permission to manage organizations in Action1.

## RELATED LINKS

[Get-Action1Organization](Get-Action1Organization.md)
[Get-Action1Organizations](../configuration/Get-Action1Organizations.md)
[New-Action1Organization](New-Action1Organization.md)
[Remove-Action1Organization](Remove-Action1Organization.md)
