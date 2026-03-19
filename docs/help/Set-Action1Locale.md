---

external help file: PSAction1-help.xml

Module Name: PSAction1

online version:

schema: 2.0.0

---

# Set-Action1Locale

## SYNOPSIS

**(DEPRECATED!)** Sets the Action1 locale used by the PSAction1 module for the current PowerShell session. Please use **Set-Action1Region** instead.

## SYNTAX

```powershell

Set-Action1Locale [-Region] <String> [<CommonParameters>]

```

## DESCRIPTION

**This function is deprecated.**

`Set-Locale` previously configured the locale(region) used by the PSAction1 module for API requests and regional formatting.

This command is retained for backward compatibility but will be removed in a

future version of the PSAction1 module.

Please use the `Set-Action1Region` command instead.

## EXAMPLES

### Example 1

```powershell

PS C:\> Set-Action1Locale -Region NorthAmerica

```

Sets the module locale, actually region, to "NorthAmerica" for the current session.

### Example 2

```powershell

PS C:\> Set-Action1Locale -Region Europe

```

Sets the module locale, actually region, to "Europe" for the current session.

## PARAMETERS

### -Region

Specifies the locale/region identifier to use.

```yaml

Type: String

Parameter Sets: (All)

Aliases:

Accepted values: NorthAmerica, Europe

Required: True

Position: 0

Default value: None

Accept pipeline input: False

Accept wildcard characters: False

```

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None. You cannot pipe objects to this command.

## OUTPUTS

### None: This command only sets a module variable for the current session.

## NOTES

This command is deprecated and will be removed in a future version.

Use **Set-Action1Region** instead.

## RELATED LINKS

[Set-Action1Region](Set-Action1Region.md)
