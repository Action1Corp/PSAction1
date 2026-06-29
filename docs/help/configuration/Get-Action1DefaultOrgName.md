---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1DefaultOrgName

## SYNOPSIS

Gets the default Action1 organization name for the current PowerShell session.

## SYNTAX

```
Get-Action1DefaultOrgName [<CommonParameters>]
```

## DESCRIPTION

`Get-Action1DefaultOrgName` returns the organization name stored by `Set-Action1DefaultOrg`.

The value is stored only for the duration of the current PowerShell session.

## EXAMPLES

### Example 1: Get the default organization name

```powershell
PS C:\> Get-Action1DefaultOrgName
```

Returns the currently configured default organization name.

## OUTPUTS

### System.String

The default organization name, or no output when a default organization is not configured.

## RELATED LINKS

[Set-Action1DefaultOrg](Set-Action1DefaultOrg.md)
[Get-Action1DefaultOrgId](Get-Action1DefaultOrgId.md)
[Get-Action1Organizations](Get-Action1Organizations.md)
