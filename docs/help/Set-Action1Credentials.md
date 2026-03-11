---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Set-Action1Credentials

## SYNOPSIS

Sets Action1 API credentials for the current PowerShell session.

## SYNTAX

```powershell
Set-Action1Credentials [-APIKey] <String> [-Secret] <String> [<CommonParameters>]
```

## DESCRIPTION

Stores Action1 APIKey and Secret in script scope variables used
by other commands in the module to authenticate API calls.

## EXAMPLES

### Example 1

```powershell
PS C:\> Set-Action1Credentials -APIKey "abc123" -Secret "secret"
```

Stores Action1 credentials for use by other PSAction1 module commands.

## PARAMETERS

### -APIKey

Action1 API key provided by the service.

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

### -Secret

Action1 API secret associated with the Action1 API key.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None. You cannot pipe objects to this command.

## OUTPUTS

### None. This command only sets module and session variables.

## NOTES

Action1 credentials are stored only for the lifetime of the PowerShell session.

## RELATED LINKS
