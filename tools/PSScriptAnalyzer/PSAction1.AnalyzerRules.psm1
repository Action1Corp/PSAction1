# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

Set-StrictMode -Version 2.0

. (Join-Path -Path $PSScriptRoot -ChildPath 'Action1.PowerShellHeader.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Action1.ApprovedNounWords.ps1')

$script:PSAction1RepositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent

$script:PSAction1ApprovedVerbs = @{}
Get-Verb | ForEach-Object {
    $script:PSAction1ApprovedVerbs[$_.Verb] = $true
}

$script:PSAction1HeaderSearchLineCount = 25

function New-PSAction1DiagnosticRecord {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Message,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.IScriptExtent] $Extent,

        [Parameter(Mandatory = $true)]
        [string] $RuleName
    )

    $severity = [Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticSeverity]::Warning

    New-Object -TypeName Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord `
        -ArgumentList $Message, $Extent, $RuleName, $severity, $null, $null, $null
}

function Get-PSAction1RelativePath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    $rootPath = [System.IO.Path]::GetFullPath($script:PSAction1RepositoryRoot)
    $rootPath = $rootPath.TrimEnd([char[]] @('\', '/'))

    if (-not $resolvedPath.StartsWith($rootPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $resolvedPath
    }

    $relativePath = $resolvedPath.Substring($rootPath.Length)
    $relativePath.TrimStart([char[]] @('\', '/'))
}

function Test-PSAction1HeaderPresence {
    param(
        [AllowNull()]
        [string[]] $Lines
    )

    if ($null -eq $Lines) {
        return $false
    }

    if ($Lines.Count -lt $script:PSAction1RequiredHeaderLines.Count) {
        return $false
    }

    $lastStartIndex = $Lines.Count - $script:PSAction1RequiredHeaderLines.Count

    for ($startIndex = 0; $startIndex -le $lastStartIndex; $startIndex++) {
        $matchesHeader = $true

        for ($offset = 0; $offset -lt $script:PSAction1RequiredHeaderLines.Count; $offset++) {
            $actualLine = $Lines[$startIndex + $offset]
            $expectedLine = $script:PSAction1RequiredHeaderLines[$offset]

            if ($actualLine -cne $expectedLine) {
                $matchesHeader = $false
                break
            }
        }

        if ($matchesHeader) {
            return $true
        }
    }

    $false
}

function Split-PSAction1NounWord {
    param(
        [AllowNull()]
        [string] $Noun
    )

    if ([string]::IsNullOrWhiteSpace($Noun)) {
        return @()
    }

    $wordMatches = [regex]::Matches($Noun, 'Action1|[A-Z]+(?=[A-Z][a-z]|\d|$)|[A-Z]?[a-z]+|\d+')
    $words = @()

    foreach ($wordMatch in $wordMatches) {
        $words += $wordMatch.Value
    }

    $words
}

function Test-PSAction1PascalCaseNoun {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Noun
    )

    if ($Noun -cnotmatch '^[A-Z][A-Za-z0-9]*$') {
        return $false
    }

    $words = @(Split-PSAction1NounWord -Noun $Noun)

    if ($words.Count -eq 0) {
        return $false
    }

    (($words -join '') -ceq $Noun)
}

function Get-PSAction1NounProofingIssue {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Noun
    )

    $words = @(Split-PSAction1NounWord -Noun $Noun)

    foreach ($word in $words) {
        if (-not $script:PSAction1ApprovedNounWords.ContainsKey($word)) {
            [pscustomobject] @{
                Message = "Noun word '$word' is not in the PSAction1 approved noun-word dictionary."
            }
        }
    }
}

function Measure-PSAction1Header {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.ScriptBlockAst] $ScriptBlockAst
    )

    $scriptPath = $ScriptBlockAst.Extent.File

    if ([string]::IsNullOrWhiteSpace($scriptPath)) {
        return
    }

    if ($ScriptBlockAst.Extent.StartLineNumber -ne 1) {
        return
    }

    $relativePath = Get-PSAction1RelativePath -Path $scriptPath

    if ($relativePath -eq $scriptPath) {
        return
    }

    $extension = [System.IO.Path]::GetExtension($scriptPath)
    $checkedExtensions = @('.ps1', '.psm1', '.psd1')

    if ($checkedExtensions -notcontains $extension) {
        return
    }

    try {
        $headerLines = Get-Content `
            -LiteralPath $scriptPath `
            -TotalCount $script:PSAction1HeaderSearchLineCount `
            -ErrorAction Stop
    }
    catch {
        $message = "Unable to read '$relativePath' while checking the Action1 header. "
        $message += $_.Exception.Message

        New-PSAction1DiagnosticRecord `
            -Message $message `
            -Extent $ScriptBlockAst.Extent `
            -RuleName $PSCmdlet.MyInvocation.InvocationName
        return
    }

    if (Test-PSAction1HeaderPresence -Lines $headerLines) {
        return
    }

    New-PSAction1DiagnosticRecord `
        -Message "File '$relativePath' must include the standard Action1 header near the top." `
        -Extent $ScriptBlockAst.Extent `
        -RuleName $PSCmdlet.MyInvocation.InvocationName
}

function Measure-PSAction1CmdletName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.ScriptBlockAst] $ScriptBlockAst
    )

    $scriptPath = $ScriptBlockAst.Extent.File

    if ([string]::IsNullOrWhiteSpace($scriptPath)) {
        return
    }

    $relativePath = Get-PSAction1RelativePath -Path $scriptPath
    $isPublic = $relativePath -match '^Public[\\/]'
    $isPrivate = $relativePath -match '^Private[\\/]'

    if (-not ($isPublic -or $isPrivate)) {
        return
    }

    $ruleName = $PSCmdlet.MyInvocation.InvocationName
    $functionAsts = $ScriptBlockAst.FindAll({
            param($ast)

            $ast -is [System.Management.Automation.Language.FunctionDefinitionAst]
        }, $true)

    foreach ($functionAst in $functionAsts) {
        $functionName = $functionAst.Name

        if ($functionName -notmatch '^([A-Za-z][A-Za-z0-9]*)-([A-Za-z][A-Za-z0-9]*)$') {
            New-PSAction1DiagnosticRecord `
                -Message "Function '$functionName' must use Verb-Noun naming." `
                -Extent $functionAst.Extent `
                -RuleName $ruleName
            continue
        }

        $verb = $Matches[1]
        $noun = $Matches[2]

        if (-not $script:PSAction1ApprovedVerbs.ContainsKey($verb)) {
            New-PSAction1DiagnosticRecord `
                -Message "Function '$functionName' uses unapproved PowerShell verb '$verb'." `
                -Extent $functionAst.Extent `
                -RuleName $ruleName
        }

        if ($isPublic -and -not $noun.StartsWith('Action1', [System.StringComparison]::Ordinal)) {
            New-PSAction1DiagnosticRecord `
                -Message "Public cmdlet '$functionName' must use the Verb-Action1... naming pattern." `
                -Extent $functionAst.Extent `
                -RuleName $ruleName
        }

        if (-not (Test-PSAction1PascalCaseNoun -Noun $noun)) {
            New-PSAction1DiagnosticRecord `
                -Message "Function '$functionName' must use PascalCase in the noun part." `
                -Extent $functionAst.Extent `
                -RuleName $ruleName
        }

        $proofingIssues = @(Get-PSAction1NounProofingIssue -Noun $noun)

        foreach ($proofingIssue in $proofingIssues) {
            New-PSAction1DiagnosticRecord `
                -Message "Function '$functionName': $($proofingIssue.Message)" `
                -Extent $functionAst.Extent `
                -RuleName $ruleName
        }
    }
}

Export-ModuleMember -Function Measure-PSAction1CmdletName, Measure-PSAction1Header
