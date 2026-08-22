---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1Organizations

## SYNOPSIS

Gets Action1 organizations available to the current account.

## SYNTAX

### AllOrganizations (Default)
```
Get-Action1Organizations [-Limit <Int32>] [<CommonParameters>]
```

### AsPage
```
Get-Action1Organizations [-AsPage] [-Limit <Int32>] [<CommonParameters>]
```

## DESCRIPTION

`Get-Action1Organizations` calls the Action1 organizations endpoint and returns
a sorted object list containing organization names, IDs, descriptions, types,
and enterprise IDs.

Results are sorted by organization name, then organization ID.

Use **AsPage** to return one object per API page. Page mode is intended for
export commands that need to process large result sets incrementally. In page
mode, each page object contains normalized organization objects in the
**Items** property and preserves the API page order.

## EXAMPLES

### Example 1: List organizations

```powershell
PS C:\> Get-Action1Organizations
```

Returns organization details available to the current account.

## PARAMETERS

### -AsPage

Returns one object per API page instead of a flattened organization list.

Each page object's **Items** property contains normalized organization objects
with `Org_Name`, `Org_ID`, `Description`, `Type`, and `EnterpriseId`
properties.

```yaml
Type: SwitchParameter
Parameter Sets: AsPage
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Limit

Specifies the page size used for paged API requests.

The command still retrieves all available pages unless **AsPage** is used by a
caller that processes each page incrementally.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 200
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe input to this command.

## OUTPUTS

### PSCustomObject

Each object contains `Org_Name`, `Org_ID`, `Description`, `Type`, and
`EnterpriseId` properties.

When **AsPage** is used, each page object contains `Items`, `PageNumber`,
`From`, `Limit`, `TotalItems`, and `NextPage` properties.

## NOTES

## RELATED LINKS

[Set-Action1DefaultOrg](Set-Action1DefaultOrg.md)
[Get-Action1DefaultOrgId](Get-Action1DefaultOrgId.md)
[Get-Action1DefaultOrgName](Get-Action1DefaultOrgName.md)
