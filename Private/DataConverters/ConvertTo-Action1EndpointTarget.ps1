# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function ConvertTo-Action1EndpointTarget {
    [CmdletBinding(DefaultParameterSetName = 'ByEndpointId')]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = 'ByEndpointId')]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$EndpointId,

        [Parameter(Mandatory = $false, ParameterSetName = 'ByEndpointObject')]
        [AllowNull()]
        [object]$EndpointObject
    )

    $resolvedEndpointId = $null
    $resolvedEndpointName = $null

    if ($PSCmdlet.ParameterSetName -eq 'ByEndpointObject') {
        if ($null -eq $EndpointObject) {
            return [pscustomobject]@{
                IsValid      = $false
                EndpointId   = $null
                EndpointName = $null
                ErrorMessage = 'Endpoint object cannot be null.'
            }
        }

        $idProperty = $EndpointObject.PSObject.Properties |
            Where-Object { $_.Name -eq 'id' } |
            Select-Object -First 1

        if ($null -eq $idProperty) {
            return [pscustomobject]@{
                IsValid      = $false
                EndpointId   = $null
                EndpointName = $null
                ErrorMessage = "Endpoint object must include an 'id' property."
            }
        }

        $resolvedEndpointId = [string]$idProperty.Value
        $nameProperty = $EndpointObject.PSObject.Properties |
            Where-Object { $_.Name -eq 'name' } |
            Select-Object -First 1

        if ($null -ne $nameProperty) {
            $rawEndpointName = [string]$nameProperty.Value

            if (-not [string]::IsNullOrWhiteSpace($rawEndpointName)) {
                $resolvedEndpointName = $rawEndpointName.Trim()
            }
        }
    }
    else {
        $resolvedEndpointId = [string]$EndpointId
    }

    if ([string]::IsNullOrWhiteSpace($resolvedEndpointId)) {
        return [pscustomobject]@{
            IsValid      = $false
            EndpointId   = $null
            EndpointName = $resolvedEndpointName
            ErrorMessage = 'Endpoint ID cannot be null, empty, or whitespace.'
        }
    }

    $resolvedEndpointId = $resolvedEndpointId.Trim()
    $parsedGuid = [guid]::Empty

    if (-not [guid]::TryParseExact($resolvedEndpointId, 'D', [ref]$parsedGuid)) {
        $errorMessage = (
            "Endpoint ID '$resolvedEndpointId' must use the standard GUID format."
        )

        return [pscustomobject]@{
            IsValid      = $false
            EndpointId   = $resolvedEndpointId
            EndpointName = $resolvedEndpointName
            ErrorMessage = $errorMessage
        }
    }

    [pscustomobject]@{
        IsValid      = $true
        EndpointId   = $resolvedEndpointId
        EndpointName = $resolvedEndpointName
        ErrorMessage = $null
    }
}
