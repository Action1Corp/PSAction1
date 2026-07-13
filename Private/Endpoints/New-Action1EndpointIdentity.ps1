# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function New-Action1EndpointIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$EndpointId,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$EndpointName
    )

    $resolvedEndpointId = $null
    $resolvedEndpointName = $null

    $resolvedEndpointId = [string]$EndpointId

    if (-not [string]::IsNullOrWhiteSpace($EndpointName)) {
        $resolvedEndpointName = $EndpointName.Trim()
    }

    if ([string]::IsNullOrWhiteSpace($resolvedEndpointId)) {
        return [pscustomobject]@{
            IsValid       = $false
            EndpointId    = $null
            EndpointName  = $resolvedEndpointName
            EndpointLabel = $null
            ErrorMessage  = 'Endpoint ID cannot be null, empty, or whitespace.'
        }
    }

    $resolvedEndpointId = $resolvedEndpointId.Trim()
    $endpointLabel = New-Action1EndpointLabel `
        -EndpointId $resolvedEndpointId `
        -EndpointName $resolvedEndpointName
    $parsedGuid = [guid]::Empty

    if (-not [guid]::TryParseExact($resolvedEndpointId, 'D', [ref]$parsedGuid)) {
        $errorMessage = (
            "Endpoint ID '$resolvedEndpointId' must use the standard GUID format."
        )

        return [pscustomobject]@{
            IsValid       = $false
            EndpointId    = $resolvedEndpointId
            EndpointName  = $resolvedEndpointName
            EndpointLabel = $endpointLabel
            ErrorMessage  = $errorMessage
        }
    }

    [pscustomobject]@{
        IsValid       = $true
        EndpointId    = $resolvedEndpointId
        EndpointName  = $resolvedEndpointName
        EndpointLabel = $endpointLabel
        ErrorMessage  = $null
    }
}
