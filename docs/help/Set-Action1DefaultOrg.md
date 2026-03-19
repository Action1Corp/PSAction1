---

external help file: PSAction1-help.xml

Module Name: PSAction1

online version:

schema: 2.0.0

---

# Set-Action1DefaultOrg

## SYNOPSIS

Sets the default Action1 organization ID for the current PowerShell session.

## SYNTAX

```powershell

Set-Action1DefaultOrg [-Org_ID] <String> [<CommonParameters>]

```

## DESCRIPTION

Stores the specified Action1 organization ID in a script scope variable used by other commands in the module. Once set, the value can be reused by commands that require an organization identifier, so it does not need to be specified repeatedly.

The value is stored only for the duration of the current PowerShell session.

## EXAMPLES

### Example 1

```powershell

PS C:\> Set-Action1DefaultOrg -Org_ID "org-12345"

```

Sets the default organization ID to org-12345 for use by other module commands.

## PARAMETERS

### -Org_ID

The identifier of the Action1 organization to use as the default for subsequent module commands.

```yaml

Type: String

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

### None. This command does not produce output. It only sets a module-level variable.

## NOTES

The default organization value is stored in a script scope variable and is

available only for the lifetime of the PowerShell session.

## RELATED LINKS
