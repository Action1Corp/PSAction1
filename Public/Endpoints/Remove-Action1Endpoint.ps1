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

        [switch]$Force
    )

    if (Initialize-Action1DefaultOrg) {
        $orgId = Get-Action1DefaultOrgId
    }

    if (-not $Script:Action1_UriMap.ContainsKey('D_Endpoint')) {
        throw "Action1 URI map key 'D_Endpoint' is not defined."
    }

    $endpoint = & $Script:Action1_UriMap['D_Endpoint'] $orgId $EndpointId
    $path = "$Script:Action1_BaseURI{0}" -f $endpoint
    $target = "endpoint '$EndpointId'"

    if ($Force) {
        $ConfirmPreference = 'None'
    }

    if (-not $PSCmdlet.ShouldProcess($target, 'Delete Action1 endpoint')) {
        Write-Action1Debug "Skipped deleting endpoint '$EndpointId'."

        [pscustomobject]@{
            EndpointId = $EndpointId
            Status     = 'Skipped'
            Response   = $null
        }
        return
    }

    Write-Action1Debug "Deleting endpoint '$EndpointId'."

    $response = Invoke-Action1ApiRequest `
        -Method DELETE `
        -Path $path `
        -Label "Delete endpoint '$EndpointId'" `
        -RawResponse

    if ($null -eq $response) {
        Write-Error ("Failed to delete endpoint '{0}'." -f $EndpointId)

        [pscustomobject]@{
            EndpointId = $EndpointId
            Status     = 'Failed'
            Response   = $null
        }
        return
    }

    Write-Action1Debug "Deleted endpoint '$EndpointId'."

    [pscustomobject]@{
        EndpointId = $EndpointId
        Status     = 'Removed'
        Response   = $response
    }
}
