---

external help file: PSAction1-help.xml

Module Name: PSAction1

online version:

schema: 2.0.0

---

# Set-Action1Interactive

## SYNOPSIS

Enables or disables interactive mode for PSAction1 module.

## SYNTAX

```powershell

Set-Action1Interactive [-Enabled] <Boolean> [<CommonParameters>]

```

## DESCRIPTION

Enables or disables interactive mode for the current PowerShell session.

When interactive mode is enabled, the PSAction1 module will prompt for the required variable values that have not been set. This helps guide users through configuration when running commands that depend on module-level variables.

When interactive mode is disabled, commands will not prompt for missing values and may fail if required variables are not set.

Action1 interactive setting is stored in a script-scoped variable and applies only to the current PowerShell session.

## EXAMPLES

### Example 1

```powershell

PS C:\> Set-Action1Interactive -Enabled $true

```

Enables interactive mode. The module will prompt for required variables that are missing.

### Example 2

```powershell

PS C:\> Set-Action1Interactive -Enabled $false

```

Disables interactive mode so commands will not prompt for missing variables.

## PARAMETERS

### -Enabled

Specifies whether PSAction1 interactive mode should be enabled or disabled.

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

### None. This command only modifies a module-level setting.

## NOTES

The interactive mode is stored in a script-scoped variable and remains active only for the lifetime of the PowerShell session.

## RELATED LINKS
