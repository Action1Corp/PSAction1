---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1Enterprise

## SYNOPSIS

Gets settings for the current Action1 enterprise.

## SYNTAX

```
Get-Action1Enterprise [<CommonParameters>]
```

## DESCRIPTION

`Get-Action1Enterprise` calls the Action1 enterprise API and returns settings
for the current enterprise. Action1 returns only the enterprise that the current
credentials can access.

The requested GET endpoint is `/enterprise`.

## EXAMPLES

### Example 1: Get current enterprise settings

```powershell
Get-Action1Enterprise
```

Gets settings for the current Action1 enterprise.

## PARAMETERS

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

This command does not accept pipeline input.

## OUTPUTS

### System.Object

Returns the enterprise object returned by Action1.

## NOTES

Action1 can return an access denied error when the caller does not have access
to view enterprise settings.

## RELATED LINKS

[Get-Action1EnterpriseId](Get-Action1EnterpriseId.md)
[Update-Action1Enterprise](Update-Action1Enterprise.md)
