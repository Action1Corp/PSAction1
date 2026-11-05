# Action1 Sign Tool

`action1sign` is a command-line tool for API users to sign Action1 configuration objects for 
[Endpoint Takeover Prevention (ETP)](https://www.action1.com/endpoint-takeover-prevention/).

## Download

Download and extract the archive for your platform from this repository's **Releases** page.
Replace `<version>` below with the release version.

| Platform | Archive |
|---|---|
| Windows (x86) | `action1sign-<version>-windows-x86.zip` |
| Linux (x64) | `action1sign-<version>-linux-x64.tar.gz` |
| macOS (Intel and Apple silicon) | `action1sign-<version>-macos-universal.tar.gz` |

## Usage

You need a configuration JSON file, an Action1 signing key file, and its passphrase. The examples 
below read the passphrase from `passphrase.txt`. Replace the example paths with your own files.

Windows PowerShell:

```powershell
.\action1sign.exe --config=config.json --action1-key=Action1.key --passphrase-file=passphrase.txt --out=signature.json
```

Linux and macOS:

```sh
./action1sign --config=config.json --action1-key=Action1.key --passphrase-file=passphrase.txt --out=signature.json
```

The tool writes the signature to the specified output file. Add `--force` to replace an existing output file. 
Omit `--out` to write the signature to stdout.

## Options

```text
--config=<path>           Config JSON file (- for stdin)
--action1-key=<path>      Action1 signing key file
--passphrase-file=<path>  Key passphrase file (or --passphrase)
--passphrase=<value>      Key passphrase (or --passphrase-file)
--out=<path>              Signature output file (default: stdout)
--force                   Replace an existing output file
--version                 Show version
--help                    Show this help
```

Use `-` for one input path to read from stdin. For example:

```sh
./action1sign --config=- --action1-key=Action1.key --passphrase-file=passphrase.txt --out=signature.json < config.json
```

## Additional Notices

- [DISCLAIMER](./DISCLAIMER.md)
- [THIRD_PARTY_INTEGRATIONS](./THIRD_PARTY_INTEGRATIONS.md)
- [SECURITY_NOTICE](./SECURITY_NOTICE.md)
- [NOTICE](./NOTICE.md)
- [TERMS_OF_USE](./TERMS_OF_USE.md)
- [THIRD_PARTY_NOTICES](./THIRD_PARTY_NOTICES.md)