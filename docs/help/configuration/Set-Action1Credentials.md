---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Set-Action1Credentials

## SYNOPSIS

Stores Action1 API credentials as SecureStrings for the current PowerShell session.

## SYNTAX

```
Set-Action1Credentials [-APIKey] <SecureString> [-Secret] <SecureString> [<CommonParameters>]
```

## DESCRIPTION

Stores the API key and secret as SecureStrings in `$Script:Action1_APIKey` and
`$Script:Action1_Secret` inside the module. Both values last only for the current
module session. This command does not write credentials to disk or make an API
request. Subsequent successful calls replace both stored credentials.

Both parameters accept only nonempty SecureStrings. Plaintext strings are no
longer accepted directly. Use `Read-Host -AsSecureString` to enter credentials,
or convert existing string variables with `ConvertTo-SecureString -AsPlainText -Force`.

When an OAuth token is needed, the module temporarily obtains plaintext from
these SecureStrings to build the authentication request. The stored variables
remain SecureStrings. Authentication requests use sensitive-data handling:
request bodies, response bodies, server error messages, and exception text are
omitted from module diagnostics. HTTP verbose, debug, warning, information, and
progress output are suppressed for these requests. HTTP status codes and fixed
failure messages remain available.

## EXAMPLES

### Example 1: Enter credentials interactively

```powershell
$apiKey = Read-Host 'Action1 API key (Client ID)' -AsSecureString
$secret = Read-Host 'Action1 API secret (Client Secret)' -AsSecureString
Set-Action1Credentials -APIKey $apiKey -Secret $secret
```

Prompts for both values as SecureStrings and stores them for use by other
PSAction1 module commands. The command produces no output.

### Example 2: Convert existing string credentials

```powershell
$apiKey = ConvertTo-SecureString -String $apiKeyText -AsPlainText -Force
$secret = ConvertTo-SecureString -String $secretText -AsPlainText -Force
Set-Action1Credentials -APIKey $apiKey -Secret $secret
```

Assumes `$apiKeyText` and `$secretText` already contain the nonempty credentials
obtained from Action1. `-AsPlainText` wraps each string as a SecureString;
without it, `ConvertTo-SecureString` expects an encrypted string representation.
Windows PowerShell 5.1 requires `-Force` with `-AsPlainText`.

## PARAMETERS

### -APIKey

Action1 API key (Client ID) provided by the service, supplied as a nonempty
`System.Security.SecureString`. Plaintext strings, null values, and empty
SecureStrings are rejected.

```yaml
Type: SecureString
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Secret

Action1 API secret (Client Secret) associated with the API key, supplied as a
nonempty `System.Security.SecureString`. Plaintext strings, null values, and
empty SecureStrings are rejected.

```yaml
Type: SecureString
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

### None

This command does not accept pipeline input.

## OUTPUTS

### None

This command updates credentials in module state and produces no output.

## NOTES

Supported in Windows PowerShell 5.1. Call this command again after starting a
new session or reloading the module.

Converting existing string variables does not erase their plaintext contents.
Use `Read-Host -AsSecureString` when plaintext input in the caller is unnecessary.
Plaintext is still needed in process memory to send the OAuth request;
SecureString does not prevent code with sufficient process access from obtaining
the credentials.

These protections cover module diagnostics and the HTTP command's output
streams. They cannot guarantee exclusion from PowerShell policy logging,
parameter-binding traces, transcripts of caller-supplied plaintext, .NET network
tracing, proxy inspection, endpoint monitoring, or memory dumps. Caught original
errors can also remain in PowerShell's `$Error` history. The module does not
disable auditing, clear error history, or change machine logging policies.

Avoid placing credential literals in commands or scripts. For sensitive event
logs, have the administrator configure access controls and
[Protected Event Logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1#protected-event-logging).

## RELATED LINKS

[Set-Action1Region](Set-Action1Region.md)

[Set-Action1Sign](Set-Action1Sign.md)
