---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Set-Action1Sign

## SYNOPSIS

Configures the Action1 signing key and stores an encrypted signing passphrase.

## SYNTAX

```text
Set-Action1Sign -Action1KeyPath <String> -PassPhrase <String> [-PassPhrasePath <String>]
 [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

`Set-Action1Sign` records the full path to an existing, nonempty Action1 signing
key file and writes the supplied passphrase to an encrypted file. The key file
is not copied or modified. No Action1 API request is made, and the command does
not verify that the key and passphrase match; this is checked when signing.

The passphrase is accepted as a string, converted to a SecureString, and
encrypted using Windows Data Protection API (DPAPI) through
`ConvertFrom-SecureString`, without a custom encryption key. Decryption requires
the same Windows user on the same computer. New files inherit the destination
directory's permissions; the command does not change file permissions.

The command replaces an existing passphrase file. Module credential paths are
updated only after the encrypted file is successfully written. The default
location is `%LOCALAPPDATA%\PSAction1\Signing\passphrase.txt`; subsequent calls
in the same module session reuse the last configured passphrase path.

Private conversion helpers handle encryption and decryption. The private signer
writes the decrypted passphrase into one temporary UTF-8 file without a BOM or
added newline. It pipes configuration JSON to Action1Sign using `--config=-`
and `--passphrase-file=<temporary path>`, captures the signature from stdout,
and removes the temporary passphrase file in `finally`, including after tool
failures. Invocation is synchronous, without an explicit timeout. Process
arguments contain file paths, not the passphrase value. A forced host
termination can interrupt cleanup and leave the temporary file behind.

`-WhatIf` skips file and directory creation, file replacement, and module-state
changes. `-Force` bypasses confirmation prompts while still honoring `-WhatIf`.

## EXAMPLES

### Example 1: Configure signing using a passphrase variable

```powershell
Set-Action1Sign -Action1KeyPath 'C:\Keys\Action1.key' -PassPhrase $passphrase
```

Uses the passphrase string already obtained from Action1 and stores it encrypted
at the default path. The command produces no output.

### Example 2: Select the encrypted passphrase file

```powershell
Set-Action1Sign -Action1KeyPath 'C:\Keys\Action1.key' `
    -PassPhrase $passphrase -PassPhrasePath 'C:\Signing\passphrase.txt'
```

Creates the destination directory when necessary and configures the module to
use this encrypted file for subsequent signing operations.

### Example 3: Preview a credential update

```powershell
Set-Action1Sign -Action1KeyPath 'C:\Keys\Action1.key' `
    -PassPhrase $passphrase -WhatIf
```

Validates the arguments and displays the intended operation without writing
files or changing the configured credential paths.

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

Passphrase string supplied by Action1 for the signing key. Null and empty
strings are rejected. The value is preserved without trimming or adding a
newline. It is encrypted before being written to disk and is not retained in
module state.

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

### -PassPhrasePath

Literal filesystem path for the DPAPI-encrypted passphrase file. Defaults to
`$Script:Action1_SignPassPhrasePath` inside the module, initially
`%LOCALAPPDATA%\PSAction1\Signing\passphrase.txt`. The resolved path is stored
in that module variable after a successful write. Existing files are replaced;
directories, file links, and the supplied key path are rejected.

This file is encrypted storage for PSAction1. It cannot be passed directly to
Action1Sign as a plaintext passphrase file.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: $Script:Action1_SignPassPhrasePath
Accept pipeline input: False
Accept wildcard characters: False
```

### -Force

Bypasses confirmation prompts. This switch does not override validation or
`-WhatIf`. Replacing an existing encrypted passphrase file does not require it.

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

Shows the intended credential update without writing files or changing module state.

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

Prompts before writing the encrypted passphrase file and updating module state.

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

This command writes the encrypted passphrase file and updates module state.

## NOTES

Supported on Windows, including Windows PowerShell 5.1.

The encrypted file persists after the session ends. Configured paths are module
session state; call `Set-Action1Sign` again after importing the module in a new
session. Reusing the default file does not automatically restore the key path.

Because `PassPhrase` is a string parameter, literal values typed into commands
can appear in PowerShell history or transcription. Encryption protects the
stored file, not the caller's command text or existing string variables.

Keep the signing key secure separately. Its permissions are not changed by this command.

## RELATED LINKS

[Set-Action1Credentials](Set-Action1Credentials.md)
