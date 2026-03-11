---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Set-Action1Debug

## SYNOPSIS

Enables or disables debug mode for PSAction1 module.

## SYNTAX

```powershell
Set-Action1Debug [-Enabled] <Boolean> [<CommonParameters>]
```

## DESCRIPTION

Sets the internal debug flag forPSAction1 module in script scope.  
When debug mode is enabled, additional diagnostic messages may be displayed by
module functions that support debugging output.

## EXAMPLES

### Example 1

```powershell
PS C:\> Set-Action1Debug -Enabled $true
```

Enables the debug mode for PSAction1 module.

### Example 2

```powershell
PS C:\> Set-Action1Debug -Enabled $false
```

Disables the debug mode for PSAction1 module.

## PARAMETERS

### -Enabled

Specifies whether the debug mode should be enabled or disabled.

```yaml
Type: Boolean
Parameter Sets: (All)
Aliases:

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

### None. This command does not return objects. It only updates an internal module variable controlling debug behavior.

## NOTES

The debug mode affects only the current PowerShell session and is stored in a script-scope variable.

## RELATED LINKS
