---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Set-Action1Locale

## SYNOPSIS

Deprecated wrapper for `Set-Action1Region`. Sets the Action1 API region used by the PSAction1 module for the current PowerShell session.

## SYNTAX

```
Set-Action1Locale [-Region] <String> [<CommonParameters>]
```

## DESCRIPTION

`Set-Action1Locale` is deprecated and is retained only for backward compatibility with earlier versions of PSAction1.

The function forwards the supplied **Region** value to `Set-Action1Region`, which configures the Action1 API region endpoint used by subsequent module commands.

Use `Set-Action1Region` in new scripts and automation.

## EXAMPLES

### Example 1

```powershell
PS C:\> Set-Action1Locale -Region NorthAmerica
```

Sets the Action1 API region to `NorthAmerica` for the current PowerShell session.

### Example 2

```powershell
PS C:\> Set-Action1Locale -Region Europe
```

Sets the Action1 API region to `Europe` for the current PowerShell session.

### Example 3

```powershell
PS C:\> Set-Action1Locale -Region 'NA-2'
```

Sets the Action1 API region using the `NA-2` region value. This command is deprecated; use `Set-Action1Region` instead.

## PARAMETERS

### -Region

Specifies the Action1 API region to use.

The value is passed directly to `Set-Action1Region`.

Accepted values:

- NorthAmerica
- NorthAmerica-2
- NA-2
- Europe
- Australia

```yaml
Type: String
Parameter Sets: (All)
Aliases:
Accepted values: NorthAmerica, NorthAmerica-2, NA-2, Europe, Australia

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe objects to this command.

## OUTPUTS

### None

This command does not write objects to the pipeline. It calls `Set-Action1Region`, which updates the module's internal region setting for the current PowerShell session.

## NOTES

This command is deprecated and may be removed in a future version of the PSAction1 module.

Use `Set-Action1Region` instead.

## RELATED LINKS

[Set-Action1Region](Set-Action1Region.md)
