# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1EndpointIdentityFromObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$EndpointObject
    )

    if ($null -eq $EndpointObject) {
        return [pscustomobject]@{
            IsValid       = $false
            EndpointId    = $null
            EndpointName  = $null
            EndpointLabel = $null
            ErrorMessage  = 'Endpoint object cannot be null.'
        }
    }

    $idProperty = $EndpointObject.PSObject.Properties |
        Where-Object { $_.Name -eq 'id' } |
        Select-Object -First 1

    if ($null -eq $idProperty) {
        return [pscustomobject]@{
            IsValid       = $false
            EndpointId    = $null
            EndpointName  = $null
            EndpointLabel = $null
            ErrorMessage  = "Endpoint object must include an 'id' property."
        }
    }

    $endpointName = $null
    $nameProperty = $EndpointObject.PSObject.Properties |
        Where-Object { $_.Name -eq 'name' } |
        Select-Object -First 1

    if ($null -ne $nameProperty) {
        $endpointName = [string]$nameProperty.Value
    }

    New-Action1EndpointIdentity `
        -EndpointId ([string]$idProperty.Value) `
        -EndpointName $endpointName
}
