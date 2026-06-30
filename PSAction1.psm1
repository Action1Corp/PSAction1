# Name: PSAction1
# Description: Powershell module for working with the Action1 API.

# Documentation: https://github.com/Action1Corp/PSAction1/
# Use Action1 Roadmap system (https://roadmap.action1.com/) to submit feedback or enhancement requests.

# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

$Script:ModuleRoot = $PSScriptRoot

$RequiredPrivateFiles = @(
    'Private\Configuration\Action1.Defaults.ps1'
    'Private\Configuration\Action1.Hosts.ps1'
    'Private\Configuration\Action1.UriMap.ps1'
    'Private\Initialization\Initialize-Action1ModuleState.ps1'
    'Private\Templates\RemediationTemplate.ps1'
    'Private\Templates\PackageDeployTemplate.ps1'
)

foreach ($RelativePath in $RequiredPrivateFiles) {
    $FullPath = Join-Path $Script:ModuleRoot $RelativePath

    if (-not (Test-Path -LiteralPath $FullPath -PathType Leaf)) {
        throw "Required module file not found: $RelativePath"
    }

    . $FullPath
}

$LoadedPrivateFiles = $RequiredPrivateFiles | ForEach-Object {
    [System.IO.Path]::GetFullPath((Join-Path $Script:ModuleRoot $_))
}

Get-ChildItem -Path (Join-Path $Script:ModuleRoot 'Private') -Filter '*.ps1' -Recurse |
    Where-Object { $LoadedPrivateFiles -notcontains $_.FullName } |
    Sort-Object FullName |
    ForEach-Object {
        . $_.FullName
    }

Get-ChildItem -Path (Join-Path $Script:ModuleRoot 'Public') -Filter '*.ps1' -Recurse |
    Sort-Object FullName |
    ForEach-Object {
        . $_.FullName
    }
