---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1EnterpriseId

## SYNOPSIS

Gets the ID of the current Action1 enterprise.

## SYNTAX

```
Get-Action1EnterpriseId [<CommonParameters>]
```

## DESCRIPTION

`Get-Action1EnterpriseId` calls `Get-Action1Enterprise`, extracts the **id**
property from the returned enterprise object, validates that the value uses the
standard GUID format, and returns the ID as a string.

Action1 returns only the enterprise that the current credentials can access.

## EXAMPLES

### Example 1: Get the current enterprise ID

```powershell
Get-Action1EnterpriseId
```

Gets the ID of the current Action1 enterprise.

## PARAMETERS

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

This command does not accept pipeline input.

## OUTPUTS

### System.String

Returns the current Action1 enterprise ID.

## NOTES

Requires permission to view enterprise settings in Action1.

## RELATED LINKS

[Get-Action1Enterprise](Get-Action1Enterprise.md)
