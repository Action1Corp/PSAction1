# PSScriptAnalyzer Procedure

Run PSScriptAnalyzer from the PSAction1 repository root with Windows PowerShell
5.1 or PowerShell 7.

## Prerequisite

```powershell
Get-Module -ListAvailable PSScriptAnalyzer
```

If the module is missing, install it for the current user:

```powershell
Install-Module PSScriptAnalyzer -Scope CurrentUser
```

## Standard Check

```powershell
.\tools\Invoke-PSScriptAnalyzer.ps1
```

Run this command from the PSAction1 repository root, the folder that contains
`PSAction1.psd1` and `PSScriptAnalyzerSettings.psd1`. If the command prints only
`PSScriptAnalyzer completed without findings.`, the check passed.

The wrapper resolves the repository path from its own location by default, so it
can also be invoked by full or relative path from another current directory. The
documented standard command still assumes the repository root for readability
and consistent local/CI usage.

Use PowerShell's standard `-Debug` switch when you want to see what the wrapper
is doing while the repository scan is running:

```powershell
.\tools\Invoke-PSScriptAnalyzer.ps1 -Debug
```

The committed settings profile gates `Error` and `Warning` findings and loads
the repository custom rules from `tools/PSScriptAnalyzer`. It excludes repo-policy
mismatches that are not useful to fix as part of normal development:

* UTF-8 BOM warnings.
* Singular-noun warnings for established public cmdlet names.
* Manifest export wildcard warnings.
* The broad ShouldProcess warning for local module-state setters.

## Custom Naming Rules

The repository custom rules check functions in `Public` and `Private` for:

* `Verb-Noun` naming.
* Approved PowerShell verb usage.
* Public cmdlet nouns that start with `Action1`.
* PascalCase noun usage.
* Noun words that exist in the approved repository vocabulary.

The custom rules also check every analyzed `.ps1`, `.psm1`, and `.psd1` file
for the standard Action1 repository header near the top of the file.

The English checks intentionally use an approved noun-word dictionary instead of
hard-coded rejected typo or phrase lists. Add accepted technical terms to
`tools/PSScriptAnalyzer/Action1.ApprovedNounWords.ps1` when the module grows.
The initial vocabulary is based on existing module cmdlet names and stable
resource/entity terms from the Action1 API Postman collection.

## Optional Informational Review

Use this when you want style cleanup findings that are not part of the standard
gate.

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse -Severity Information -Settings .\PSScriptAnalyzerSettings.psd1 |
    Sort-Object RuleName, ScriptPath, Line |
    Format-Table Severity, RuleName, ScriptPath, Line, Message -Wrap
```

