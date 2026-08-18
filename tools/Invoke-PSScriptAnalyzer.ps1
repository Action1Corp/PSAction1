# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

<#
.SYNOPSIS
Runs the repository PSScriptAnalyzer check.

.DESCRIPTION
Runs PSScriptAnalyzer with the repository settings and custom PSAction1 rules.
The script writes human-readable findings and does not modify files.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $Path = (Split-Path -Path $PSScriptRoot -Parent)
)

Set-StrictMode -Version 2.0

$debugLoggingEnabled = $PSBoundParameters.ContainsKey('Debug')

function Write-PSScriptAnalyzerDebug {
    param(
        [Parameter(Position = 0)]
        [AllowEmptyString()]
        [AllowNull()]
        [string] $Message = ''
    )

    if (-not $debugLoggingEnabled) {
        return
    }

    Write-Information -MessageData "DEBUG: $Message" -InformationAction Continue
}

Write-PSScriptAnalyzerDebug 'Starting PSAction1 PSScriptAnalyzer check.'

$scriptAnalyzerCommand = Get-Command -Name Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue

if ($null -eq $scriptAnalyzerCommand) {
    throw "PSScriptAnalyzer is not installed. Run: Install-Module PSScriptAnalyzer -Scope CurrentUser"
}

Write-PSScriptAnalyzerDebug "Using PSScriptAnalyzer command: $($scriptAnalyzerCommand.Source)"

$repoRoot = (Resolve-Path -Path $Path).Path
Write-PSScriptAnalyzerDebug "Repository root: $repoRoot"

$settingsPath = Join-Path -Path $repoRoot -ChildPath 'PSScriptAnalyzerSettings.psd1'
Write-PSScriptAnalyzerDebug "Settings path: $settingsPath"

if (-not (Test-Path -Path $settingsPath -PathType Leaf)) {
    throw "PSScriptAnalyzer settings file was not found: $settingsPath"
}

$customRulePath = Join-Path -Path $repoRoot -ChildPath 'tools\PSScriptAnalyzer\PSAction1.AnalyzerRules.psm1'
Write-PSScriptAnalyzerDebug "Custom rule path: $customRulePath"

if (-not (Test-Path -Path $customRulePath -PathType Leaf)) {
    throw "PSAction1 custom analyzer rule module was not found: $customRulePath"
}

$originalLocation = Get-Location
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$results = @()

try {
    Write-PSScriptAnalyzerDebug "Changing location from '$originalLocation' to '$repoRoot'."
    Set-Location -Path $repoRoot

    $scriptAnalyzerParams = @{
        Path     = $repoRoot
        Recurse  = $true
        Settings = $settingsPath
    }

    Write-PSScriptAnalyzerDebug 'Invoking PSScriptAnalyzer. This can take a while on the full repository.'
    $results = @(Invoke-ScriptAnalyzer @scriptAnalyzerParams)
    Write-PSScriptAnalyzerDebug "PSScriptAnalyzer returned $($results.Count) finding(s)."
}
finally {
    Set-Location -Path $originalLocation
    Write-PSScriptAnalyzerDebug "Restored location to '$originalLocation'."
    $stopwatch.Stop()
    Write-PSScriptAnalyzerDebug "PSScriptAnalyzer check elapsed time: $($stopwatch.Elapsed)."
}

if ($results.Count -eq 0) {
    Write-Output 'PSScriptAnalyzer completed without findings.'
    return
}

$sortedResults = $results | Sort-Object Severity, RuleName, ScriptPath, Line, Column

$sortedResults |
    Format-Table Severity, RuleName, ScriptPath, Line, Column, Message -Wrap |
    Out-String -Width 240 |
    Write-Output

throw "PSScriptAnalyzer reported $($results.Count) issue(s)."
