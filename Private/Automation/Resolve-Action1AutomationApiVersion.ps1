# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Resolve-Action1AutomationApiVersion {
    [CmdletBinding()]
    param(
        [ValidateSet('Auto', '3.0', '4.0')]
        [string]$ApiVersion = 'Auto'
    )

    if ($ApiVersion -ne 'Auto') {
        return $ApiVersion
    }

    if ($Script:Action1_BaseURI -match '/api/(3\.0|4\.0)/?$') {
        return $Matches[1]
    }

    throw 'Set an Action1 region or specify ApiVersion 3.0 or 4.0 explicitly.'
}
