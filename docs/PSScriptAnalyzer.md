# PSScriptAnalyzer Procedure

Run PSScriptAnalyzer from the repository root with Windows PowerShell 5.1 or
PowerShell 7.

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
$repoRoot = (Get-Location).Path

$scriptAnalyzerParams = @{
    Path     = $repoRoot
    Recurse  = $true
    Settings = Join-Path $repoRoot 'PSScriptAnalyzerSettings.psd1'
}

$results = @(Invoke-ScriptAnalyzer @scriptAnalyzerParams)

$results |
    Sort-Object Severity, RuleName, ScriptPath, Line |
    Format-Table Severity, RuleName, ScriptPath, Line, Message -Wrap

if ($results.Count -gt 0) {
    throw "PSScriptAnalyzer reported $($results.Count) issue(s)."
}

Write-Host 'PSScriptAnalyzer completed without findings.'
```

Run this command from the repository root. If the command prints only
`PSScriptAnalyzer completed without findings.`, the check passed.

The committed settings profile gates `Error` and `Warning` findings. It excludes
repo-policy mismatches that are not useful to fix as part of normal development:

* UTF-8 BOM warnings.
* Singular-noun warnings for established public cmdlet names.
* Manifest export wildcard warnings.
* The broad ShouldProcess warning for local module-state setters.

## Optional Informational Review

Use this when you want style cleanup findings that are not part of the standard
gate.

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse -Severity Information |
    Sort-Object RuleName, ScriptPath, Line |
    Format-Table Severity, RuleName, ScriptPath, Line, Message -Wrap
```

Do not update `en-US/PSAction1-help.xml` after analyzer-only changes.
