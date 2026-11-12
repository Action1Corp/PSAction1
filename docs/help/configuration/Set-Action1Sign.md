---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Set-Action1Sign

## SYNOPSIS

Configures the Action1 signing key and SecureString passphrase for the current session.

## SYNTAX

```text
Set-Action1Sign -Action1KeyPath <String> -PassPhrase <SecureString> [-Force]
 [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

`Set-Action1Sign` records the full path to an existing, nonempty Action1 signing
key file in `$Script:Action1_SignKeyPath` and retains the passphrase as a
SecureString in `$Script:Action1_SignPassPhrase` inside the module. Both values
last only for the current module session. The command does not write a
passphrase file, copy or modify the key file, or make an Action1 API request.
It does not verify that the key and passphrase match; this is checked when signing.

The passphrase parameter is a SecureString. A custom argument transformation
converts nonempty plaintext strings to SecureString during parameter binding,
so existing string-based calls continue to work. Existing nonempty SecureString
values are accepted directly. The command body receives and stores only the
SecureString. Subsequent successful calls replace the configured credentials.

The private signer calls `Test-Action1SignTool` before accessing the passphrase
contents. It writes configuration JSON to a temporary UTF-8 file without a BOM,
then obtains the plaintext passphrase only for the native invocation and pipes
it to Action1Sign using `--passphrase-file=-`. The configuration is supplied
through `--config=<temporary path>` because only one input can use stdin.
The passphrase value is not included in process arguments or written to a file.
Windows PowerShell sends the stdin value as a UTF-8 line with a terminating newline.

Windows PowerShell 5.1 has no `ConvertFrom-SecureString -AsPlainText` parameter.
The signer uses `New-Object System.Net.NetworkCredential` with the SecureString
and reads its `Password` property to obtain plaintext for stdin. No network
connection or authentication occurs during this conversion.

The signer captures the signature JSON from stdout and removes the temporary
configuration file in `finally`, including after tool failures. Invocation is
synchronous, without an explicit timeout. A forced host termination can interrupt
cleanup and leave the temporary configuration file behind.

`-WhatIf` skips module-state changes. `-Force` bypasses confirmation prompts
while still honoring `-WhatIf`.

## EXAMPLES

### Example 1: Configure signing using a passphrase variable

```powershell
Set-Action1Sign -Action1KeyPath 'C:\Keys\Action1.key' -PassPhrase $passphrase
```

Uses the passphrase string already obtained from Action1, converts it to
SecureString during binding, and stores it in module memory for this session.
The command produces no output.

### Example 2: Preview a credential update

```powershell
Set-Action1Sign -Action1KeyPath 'C:\Keys\Action1.key' `
    -PassPhrase $passphrase -WhatIf
```

Validates the arguments and displays the intended operation without changing
the configured key path or passphrase.

### Example 3: Supply a SecureString directly

```powershell
$passphrase = Read-Host 'Action1 signing passphrase' -AsSecureString
Set-Action1Sign -Action1KeyPath 'C:\Keys\Action1.key' -PassPhrase $passphrase
```

Accepts the existing SecureString without converting it from plaintext again.

## PARAMETERS

### -Action1KeyPath

Literal path to an existing, nonempty Action1 signing key file. Relative paths
are resolved against the current PowerShell location. The full path is stored
in `$Script:Action1_SignKeyPath` inside the module. Wildcards are not expanded.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PassPhrase

Passphrase supplied by Action1 for the signing key. Accepts a nonempty plaintext
string or SecureString. Plaintext is converted to SecureString during parameter
binding, before the command body runs. Null, empty, and unsupported input types
are rejected. The stored value is preserved without trimming or adding a newline.
It is retained as a SecureString in `$Script:Action1_SignPassPhrase` for the
current module session and is not written to disk.

```yaml
Type: SecureString
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Force

Bypasses confirmation prompts. This switch does not override validation or
`-WhatIf`. Replacing the configured credentials does not require it.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIf

Shows the intended credential update without changing module state.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: wi

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Confirm

Prompts before updating the signing credentials in module state.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters

This cmdlet supports the common parameters. For more information, see
[about_CommonParameters](https://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

This command does not accept pipeline input.

## OUTPUTS

### None

This command updates the signing credentials in module state and produces no output.

## NOTES

Supported on Windows, including Windows PowerShell 5.1.

Neither the key path nor the passphrase is persisted between PowerShell sessions.
Call `Set-Action1Sign` again after starting a new session or reloading the module.
The key file itself remains at the user-supplied path. Previously created
encrypted passphrase files are no longer used and are not deleted by this command.

Although the parameter type is SecureString, accepted plaintext literals can
still appear in PowerShell history or transcription. Parameter transformation
does not erase the caller's original string variable or command text. Use
`Read-Host -AsSecureString` when plaintext input in the caller is unnecessary.
Signing temporarily exposes plaintext in process memory and stdin buffers for
the native signing tool. SecureString and module scope do not prevent code with
sufficient access to the process from obtaining credentials.

Keep the signing key secure separately. Its permissions are not changed by this command.

## RELATED LINKS

[Set-Action1Credentials](Set-Action1Credentials.md)
