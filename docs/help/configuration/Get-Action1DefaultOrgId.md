---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1DefaultOrgId

## SYNOPSIS

Gets the default Action1 organization ID for the current PowerShell session.

## SYNTAX

```
Get-Action1DefaultOrgId [<CommonParameters>]
```

## DESCRIPTION

`Get-Action1DefaultOrgId` returns the organization ID stored by `Set-Action1DefaultOrg`.

The value is stored only for the duration of the current PowerShell session.

## EXAMPLES

### Example 1: Get the default organization ID

```powershell
PS C:\> Get-Action1DefaultOrgId
```

Returns the currently configured default organization ID.

## PARAMETERS

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### System.String

The default organization ID, or no output when a default organization is not configured.

## NOTES

## RELATED LINKS

[Set-Action1DefaultOrg](Set-Action1DefaultOrg.md)
[Get-Action1DefaultOrgName](Get-Action1DefaultOrgName.md)
[Get-Action1Organizations](Get-Action1Organizations.md)