# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Set-Action1Interactive {
    param(
        [Parameter(Mandatory)]
        [boolean]$Enabled
    )
    if ($Enabled) { Write-Action1Debug "Interactive mode enabled, you will be prompted for variables that are required but not set." }
    $Script:Action1_Interactive = $Enabled
}