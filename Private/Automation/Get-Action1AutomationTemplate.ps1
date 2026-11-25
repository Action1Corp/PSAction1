# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1AutomationTemplate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('RunNow', 'Schedule', 'RunScript', 'DeployUpdate', 'DeployPackage')]
        [string]$Name,

        [ValidateSet('3.0', '4.0')]
        [string]$ApiVersion = '3.0'
    )

    if ($Name -in @('RunNow', 'Schedule')) {
        $relativePath = "Private\Templates\Automation\Api$($ApiVersion[0])\$Name.json"
    }
    else {
        $relativePath = "Private\Templates\Automation\Actions\$Name.json"
    }

    $path = Join-Path $Script:ModuleRoot $relativePath
    Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
}
