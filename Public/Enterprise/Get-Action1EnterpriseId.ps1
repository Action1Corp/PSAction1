# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1EnterpriseId {
    [CmdletBinding()]
    param()

    Write-Action1Debug 'Getting current Action1 enterprise ID.'

    $enterprise = Get-Action1Enterprise -ErrorAction Stop

    if ($null -eq $enterprise) {
        $message = 'No Action1 enterprise was returned.'
        Write-Error $message -ErrorAction Stop
    }

    $enterpriseId = Get-FirstPropertyValue `
        -InputObject $enterprise `
        -PropertyName @('id')

    if (-not (Test-Guid $enterpriseId)) {
        $message = "Action1 enterprise ID '$enterpriseId' must use the "
        $message += 'standard GUID format.'
        Write-Error $message -ErrorAction Stop
    }

    return $enterpriseId
}
