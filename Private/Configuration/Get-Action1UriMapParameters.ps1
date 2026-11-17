# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1UriMapParameters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [scriptblock]$UriPathBuilder
    )

    if ($null -eq $UriPathBuilder.Ast.ParamBlock) {
        return
    }

    $UriPathBuilder.Ast.ParamBlock.Parameters |
        ForEach-Object { $_.Name.VariablePath.UserPath }
}
