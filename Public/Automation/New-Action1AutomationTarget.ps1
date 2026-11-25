# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function New-Action1AutomationTarget {
    [CmdletBinding(PositionalBinding = $false)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ -not [string]::IsNullOrWhiteSpace($_) })]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Endpoint', 'EndpointGroup')]
        [string]$Type
    )

    $targetType = 'Endpoint'
    if ($Type -eq 'EndpointGroup') {
        $targetType = 'EndpointGroup'
    }
    if ($targetType -eq 'Endpoint') {
        $null = Test-Guid -Guid $Id -Label 'Endpoint ID'
    }

    [pscustomobject][ordered]@{
        id   = $Id
        type = $targetType
    }
}
