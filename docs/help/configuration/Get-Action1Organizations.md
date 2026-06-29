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

```
Get-Action1Organizations [<CommonParameters>]
```

## DESCRIPTION

`Get-Action1Organizations` calls the Action1 organizations endpoint and returns a sorted object list containing organization names and IDs.

Results are sorted by organization name, then organization ID.

## EXAMPLES

### Example 1: List organizations

```powershell
PS C:\> Get-Action1Organizations
```

Returns organization names and IDs available to the current account.

## PARAMETERS

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### PSCustomObject

Each object contains `Org_Name` and `Org_ID` properties.

## NOTES

## RELATED LINKS

[Set-Action1DefaultOrg](Set-Action1DefaultOrg.md)
[Get-Action1DefaultOrgId](Get-Action1DefaultOrgId.md)
[Get-Action1DefaultOrgName](Get-Action1DefaultOrgName.md)
