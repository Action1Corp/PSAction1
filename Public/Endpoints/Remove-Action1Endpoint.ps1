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
            $ParsedGuid = [guid]::Empty
            [guid]::TryParseExact($_, 'D', [ref]$ParsedGuid)
        })]
        [string]$EndpointId,

        [switch]$Force
    )

    if (Initialize-Action1DefaultOrg) {
        $Org_ID = Get-Action1DefaultOrgId
    }

    if (-not $Script:Action1_UriMap.ContainsKey('D_Endpoint')) {
        throw "Action1 URI map key 'D_Endpoint' is not defined."
    }

    $Endpoint = & $Script:Action1_UriMap['D_Endpoint'] $Org_ID $EndpointId
    $Path = "$Script:Action1_BaseURI{0}" -f $Endpoint
    $Target = "endpoint '$EndpointId'"

    if ($Force) {
        $ConfirmPreference = 'None'
    }

    if (-not $PSCmdlet.ShouldProcess($Target, 'Delete Action1 endpoint')) {
        Write-Action1Debug "Skipped deleting endpoint '$EndpointId'."

        [pscustomobject]@{
            EndpointId = $EndpointId
            Status     = 'Skipped'
            Response   = $null
        }
        return
    }

    Write-Action1Debug "Deleting endpoint '$EndpointId'."

    $Response = Invoke-Action1ApiRequest `
        -Method DELETE `
        -Path $Path `
        -Label "Delete endpoint '$EndpointId'" `
        -RawResponse

    if ($null -eq $Response) {
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
        Response   = $Response
    }
}
