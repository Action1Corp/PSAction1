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

$ConfigurationFiles = @(
    'Private\Configuration\Action1.Defaults.ps1'
    'Private\Configuration\Action1.Hosts.ps1'
    'Private\Configuration\Action1.UriMap.ps1'
    'Private\Initialization\Initialize-Action1ModuleState.ps1'
    'Private\Templates\RemediationTemplate.ps1'
    'Private\Templates\PackageDeployTemplate.ps1'
)

foreach ($RelativePath in $ConfigurationFiles) {
    . (Join-Path $Script:ModuleRoot $RelativePath)
}

Get-ChildItem -Path (Join-Path $Script:ModuleRoot 'Private') -Filter '*.ps1' -Recurse |
    Where-Object {
        $_.FullName -notmatch '\\Private\\Configuration\\' -and
        $_.FullName -notmatch '\\Private\\Initialization\\' -and
        $_.FullName -notmatch '\\Private\\Templates\\'
    } |
    Sort-Object FullName |
    ForEach-Object {
        . $_.FullName
    }

Get-ChildItem -Path (Join-Path $Script:ModuleRoot 'Public') -Filter '*.ps1' -Recurse |
    Sort-Object FullName |
    ForEach-Object {
        . $_.FullName
    }
