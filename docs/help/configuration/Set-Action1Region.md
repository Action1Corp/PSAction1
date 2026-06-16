---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Set-Action1Region

## SYNOPSIS

Sets the Action1 API region endpoint used by the PSAction1 module.

## SYNTAX

```
Set-Action1Region [-Region] <String> [<CommonParameters>]
```

## DESCRIPTION

`Set-Action1Region` configures the base Action1 API endpoint used by the PSAction1 module for subsequent requests in the current PowerShell session.

The command updates the module's internal region setting by selecting one of the supported regional API endpoints from the module's internal host lookup table.

Run this command before calling Action1 API commands when you need to target a specific Action1 regional environment.

## EXAMPLES

### Example 1

```powershell
PS C:\> Set-Action1Region -Region Europe
```

Configures the PSAction1 module to use the Europe API endpoint.

### Example 2

```powershell
PS C:\> Set-Action1Region -Region NorthAmerica
```

Configures the PSAction1 module to use the North America API endpoint.

### Example 3

```powershell
PS C:\> Set-Action1Region -Region Australia
```

Configures the PSAction1 module to use the Australia API endpoint.

### Example 4

```powershell
PS C:\> Set-Action1Region -Region 'NorthAmerica-2'
```

Configures the PSAction1 module to use the NorthAmerica-2 API endpoint.

### Example 5

```powershell
PS C:\> Set-Action1Region -Region 'NA-2'
```

Configures the PSAction1 module to use the NA-2 API endpoint value.

## PARAMETERS

### -Region

Specifies the Action1 API region to use.

Accepted values are:

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

This command does not return output. It sets an internal module variable used to determine the Action1 API base URI for the current PowerShell session.

## NOTES

This command affects all subsequent PSAction1 commands in the current PowerShell session that use the module's configured Action1 API base URI.

Use this command before making API requests if the default regional endpoint is not the one you want to target.

## RELATED LINKS

[about_PSAction1](about_PSAction1.md)

[Set-Action1Locale](Set-Action1Locale.md)
