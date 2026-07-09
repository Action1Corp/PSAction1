# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Remove-Action1Endpoint {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            $parsedGuid = [guid]::Empty
            [guid]::TryParseExact($_, 'D', [ref]$parsedGuid)
        })]
        [string]$EndpointId,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$EndpointName,

        [switch]$Force
    )

    if (Initialize-Action1DefaultOrg) {
        $orgId = Get-Action1DefaultOrgId
    }

    $uriPathBuilder = Get-UriMapValue -Key 'D_Endpoint'

    $uri = & $uriPathBuilder $orgId $EndpointId
    $path = "$Script:Action1_BaseURI{0}" -f $uri
    $resolvedEndpointName = $null

    if ($Force) {
        $ConfirmPreference = 'None'
    }

    if (-not [string]::IsNullOrWhiteSpace($EndpointName)) {
        $resolvedEndpointName = $EndpointName.Trim()
    }

    $endpointLabel = "endpoint with id '$EndpointId'"

    if ($null -ne $resolvedEndpointName) {
        $endpointLabel = "$endpointLabel and name '$resolvedEndpointName'"
    }

    if (-not $PSCmdlet.ShouldProcess($endpointLabel, 'Delete endpoint')) {
        Write-Action1Debug "Skipped deleting $endpointLabel."

        [pscustomobject]@{
            EndpointId   = $EndpointId
            EndpointName = $resolvedEndpointName
            Status       = 'Skipped'
            Response     = $null
        }
        return
    }

    Write-Action1Debug "Deleting $endpointLabel."

    $response = Invoke-Action1ApiRequest `
        -Method DELETE `
        -Path $path `
        -Label "Delete $endpointLabel" `
        -RawResponse

    if ($null -eq $response) {
        Write-Error "Failed to delete $endpointLabel."

        [pscustomobject]@{
            EndpointId   = $EndpointId
            EndpointName = $resolvedEndpointName
            Status       = 'Failed'
            Response     = $null
        }
        return
    }

    Write-Action1Debug "$endpointLabel was deleted successfully."

    [pscustomobject]@{
        EndpointId   = $EndpointId
        EndpointName = $resolvedEndpointName
        Status       = 'Removed'
        Response     = $response
    }
}
