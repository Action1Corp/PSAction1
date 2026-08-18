# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function New-Action1EndpointLabel {
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

    if ([string]::IsNullOrWhiteSpace($EndpointId)) {
        return $null
    }

    $endpointLabel = "endpoint with id '$($EndpointId.Trim())'"

    if (-not [string]::IsNullOrWhiteSpace($EndpointName)) {
        $endpointLabel = (
            "$endpointLabel and name '$($EndpointName.Trim())'"
        )
    }

    $endpointLabel
}
