# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Remove-Action1Endpoint {
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High',
        DefaultParameterSetName = 'ByEndpointId'
    )]
    param(
        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'ByEndpointId',
            Position = 0
        )]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$EndpointId,

        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'ByEndpointObject',
            ValueFromPipeline = $true
        )]
        [AllowNull()]
        [object]$EndpointObject,

        [switch]$Force
    )

    process {
        if ($PSCmdlet.ParameterSetName -eq 'ByEndpointObject') {
            $endpointIdentity = Get-Action1EndpointIdentityFromObject `
                -EndpointObject $EndpointObject
        }
        else {
            $endpointIdentity = New-Action1EndpointIdentity `
                -EndpointId $EndpointId
        }

        if (-not $endpointIdentity.IsValid) {
            Write-Action1Debug $endpointIdentity.ErrorMessage
            Write-Error $endpointIdentity.ErrorMessage

            [pscustomobject]@{
                EndpointId   = $endpointIdentity.EndpointId
                EndpointName = $endpointIdentity.EndpointName
                Status       = 'Invalid'
                Response     = $null
            }
            return
        }

        if (Initialize-Action1DefaultOrg) {
            $orgId = Get-Action1DefaultOrgId
        }

        $uriPathBuilder = Get-UriMapValue -Key 'D_Endpoint'

        $uri = & $uriPathBuilder $orgId $endpointIdentity.EndpointId
        $path = "$Script:Action1_BaseURI{0}" -f $uri

        if ($Force) {
            $ConfirmPreference = 'None'
        }

        $endpointLabel = $endpointIdentity.EndpointLabel

        if (-not $PSCmdlet.ShouldProcess($endpointLabel, 'Delete endpoint')) {
            Write-Action1Debug "Skipped deleting $endpointLabel."

            [pscustomobject]@{
                EndpointId   = $endpointIdentity.EndpointId
                EndpointName = $endpointIdentity.EndpointName
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
                EndpointId   = $endpointIdentity.EndpointId
                EndpointName = $endpointIdentity.EndpointName
                Status       = 'Failed'
                Response     = $null
            }
            return
        }

        Write-Action1Debug "$endpointLabel was deleted successfully."

        [pscustomobject]@{
            EndpointId   = $endpointIdentity.EndpointId
            EndpointName = $endpointIdentity.EndpointName
            Status       = 'Removed'
            Response     = $response
        }
    }
}
