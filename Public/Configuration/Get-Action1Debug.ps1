# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Get-Action1Debug {
    [CmdletBinding()]
    param()

    Write-Action1Debug 'Getting debug mode state.'
    return [bool]$Script:Action1_DebugEnabled
}
