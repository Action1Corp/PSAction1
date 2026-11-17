---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Set-Action1Credentials

## SYNOPSIS

Stores Action1 API credentials for the current PowerShell session.

## SYNTAX

```
Set-Action1Credentials [-APIKey] <String> [-Secret] <Object> [<CommonParameters>]
```

## DESCRIPTION

Stores the API key as a string in `$Script:Action1_APIKey` and the secret as a
SecureString in `$Script:Action1_Secret` inside the module. Both values last only
for the current module session. This command does not write credentials to disk
or make an API request. Subsequent successful calls replace both stored credentials.

The API key must be a nonempty string. `Secret` is expected to be a nonempty
`System.Security.SecureString`. Plaintext strings are accepted only temporarily
for backward compatibility, and support for them will be removed soon. A plaintext
secret produces an insecurity and upcoming-deprecation warning, then is converted
to a SecureString before storage. Other secret types are rejected with an error
without changing either stored credential. Use `Read-Host -AsSecureString` to
enter the secret, or convert an existing string variable with
`ConvertTo-SecureString -AsPlainText -Force`.

When an OAuth token is needed, the module uses the API key string and temporarily
obtains plaintext from the stored secret to build the authentication request.
The stored secret remains a SecureString. Authentication requests use
sensitive-data handling: request bodies, response bodies, server error messages,
and exception text are omitted from module diagnostics. HTTP verbose, debug, warning, information, and
progress output are suppressed for these requests. HTTP status codes and fixed
failure messages remain available.

## EXAMPLES

### Example 1: Enter credentials interactively

```powershell
$apiKey = Read-Host 'Action1 API key (Client ID)'
$secret = Read-Host 'Action1 API secret (Client Secret)' -AsSecureString
Set-Action1Credentials -APIKey $apiKey -Secret $secret
```

Prompts for the API key as a string and the secret as a SecureString for use by
other PSAction1 module commands. The command produces no output.

### Example 2: Convert an existing string secret

```powershell
$secret = ConvertTo-SecureString -String $secretText -AsPlainText -Force
Set-Action1Credentials -APIKey $apiKeyText -Secret $secret
```

Assumes `$apiKeyText` and `$secretText` already contain the nonempty credentials
obtained from Action1. `-AsPlainText` wraps the secret string as a SecureString;
without it, `ConvertTo-SecureString` expects an encrypted string representation.
Windows PowerShell 5.1 requires `-Force` with `-AsPlainText`.

### Example 3: Pass an existing string secret during migration

```powershell
Set-Action1Credentials -APIKey $apiKeyText -Secret $secretText
```

Plaintext secret input is accepted only temporarily for backward compatibility
and will be removed soon. This example produces a warning and stores the secret
as a SecureString. `Secret` is expected to be a SecureString; update callers as
shown in the preceding examples.

## PARAMETERS

### -APIKey

Action1 API key (Client ID) provided by the service, supplied as a nonempty
string. Null and empty strings are rejected. Supply the Client ID directly;
it is stored as a string.

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

Action1 API secret (Client Secret) associated with the API key, expected to be a
nonempty `System.Security.SecureString`. Plaintext strings are accepted only
temporarily for backward compatibility, and support for them will be removed soon.
They produce an insecurity and upcoming-deprecation warning and are converted to
a SecureString before storage. Null values, empty strings, empty SecureStrings,
and all other types are rejected. Rejected values leave both stored credentials
unchanged.

```yaml
Type: Object
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

Callers that previously supplied the API key as a SecureString must now supply
the Client ID as a string. SecureString secrets remain supported.

Converting an existing string secret does not erase its plaintext contents.
Use `Read-Host -AsSecureString` when plaintext secret input in the caller is
unnecessary.
Plaintext is still needed in process memory to send the OAuth request;
SecureString does not prevent code with sufficient process access from obtaining
the secret. The API key (Client ID) is stored as a string.

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
