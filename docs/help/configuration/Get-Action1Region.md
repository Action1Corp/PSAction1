---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1Region

## SYNOPSIS

Gets the configured Action1 API region for the current PowerShell session.

## SYNTAX

```
Get-Action1Region [<CommonParameters>]
```

## DESCRIPTION

`Get-Action1Region` returns the Action1 API region configured by `Set-Action1Region`.

The value is stored only for the duration of the current PowerShell session.

If the region name is not available but the module has a configured API base URI, the command tries to resolve the region name from the module's internal host lookup table.

## EXAMPLES

### Example 1: Get the configured Action1 region

```powershell
PS C:\> Get-Action1Region
```

Returns the currently configured Action1 API region.

### Example 2: Set and verify the Action1 region

```powershell
PS C:\> Set-Action1Region -Region Europe
PS C:\> Get-Action1Region
Europe
```

Configures the PSAction1 module to use the Europe API endpoint, then returns the configured region.

## INPUTS

### None

You cannot pipe objects to this command.

## OUTPUTS

### System.String

The configured Action1 API region, or no output when a region is not configured.

## NOTES

`Get-Action1Region` returns the region name, not the full Action1 API base URI.

When the region is inferred from the configured API base URI, duplicate host aliases resolve to the first matching region in the module's internal host lookup table.

## RELATED LINKS

[Set-Action1Region](Set-Action1Region.md)

[about_PSAction1](about_PSAction1.md)
