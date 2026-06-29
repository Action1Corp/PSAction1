---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1Debug

## SYNOPSIS

Gets the PSAction1 module debug mode state for the current PowerShell session.

## SYNTAX

```
Get-Action1Debug [<CommonParameters>]
```

## DESCRIPTION

`Get-Action1Debug` returns the debug mode state stored by `Set-Action1Debug`.

The value is stored only for the duration of the current PowerShell session.

## EXAMPLES

### Example 1: Get the debug mode state

```powershell
PS C:\> Get-Action1Debug
False
```

Returns `$true` when debug mode is enabled and `$false` when debug mode is disabled.

### Example 2: Set and verify the debug mode state

```powershell
PS C:\> Set-Action1Debug -Enabled $true
PS C:\> Get-Action1Debug
True
```

Enables debug mode for PSAction1 module, then returns the configured state.

## INPUTS

### None

You cannot pipe objects to this command.

## OUTPUTS

### System.Boolean

The current PSAction1 module debug mode state.

## NOTES

Debug mode affects only the current PowerShell session and is stored in a script-scope variable.

## RELATED LINKS

[Set-Action1Debug](Set-Action1Debug.md)
