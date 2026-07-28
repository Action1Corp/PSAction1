---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1Organization

## SYNOPSIS

Gets one Action1 organization by organization ID or organization name.

## SYNTAX

### ByOrgId (Default)
```
Get-Action1Organization [-OrgID] <String> [<CommonParameters>]
```

### ByOrgName
```
Get-Action1Organization -OrgName <String> [<CommonParameters>]
```

## DESCRIPTION

`Get-Action1Organization` calls the Action1 organizations API for a specific
organization and returns the organization object returned by Action1.

The command accepts an organization ID in standard GUID format, or an
organization name. When **-OrgName** is used, the command resolves the name with
the same lookup behavior as `Set-Action1DefaultOrg -Org_Name`.

## EXAMPLES

### Example 1: Get an organization

```powershell
Get-Action1Organization -OrgID '88c8b425-871e-4ff6-9afc-00df8592c6db'
```

Gets the specified organization.

### Example 2: Get an organization by name

```powershell
Get-Action1Organization -OrgName 'Accounting'
```

Resolves the organization named Accounting and gets that organization.

## PARAMETERS

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

### -OrgName

Specifies the organization name.

The command resolves the name by calling `Resolve-Action1OrganizationByName`.
If the name is not found or is not unique, the command writes a terminating error.

```yaml
Type: String
Parameter Sets: ByOrgName
Aliases: Org_Name

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

None. This command does not accept pipeline input.

## OUTPUTS

### System.Object

Returns the organization object returned by Action1.

## NOTES

The requested GET endpoint was implemented as `/organizations/{orgId}`.

## RELATED LINKS

[Get-Action1Organizations](../configuration/Get-Action1Organizations.md)
[New-Action1Organization](New-Action1Organization.md)
[Update-Action1Organization](Update-Action1Organization.md)
[Remove-Action1Organization](Remove-Action1Organization.md)
