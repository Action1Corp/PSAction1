# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Update-Action1Endpoint {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            $parsedGuid = [guid]::Empty
            [guid]::TryParseExact($_, 'D', [ref]$parsedGuid)
        })]
        [string]$EndpointId,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Comment
    )

    $body = @{}

    if ($PSBoundParameters.ContainsKey('Name')) {
        $body.name = $Name
    }

    if ($PSBoundParameters.ContainsKey('Comment')) {
        $body.comment = $Comment
    }

    if ($body.Count -eq 0) {
        Write-Error "Specify at least one value to update: -Name or -Comment."
        return
    }

    if (Initialize-Action1DefaultOrg) {
        $orgId = Get-Action1DefaultOrgId
    }

    if (-not $Script:Action1_UriMap.ContainsKey('U_Endpoint')) {
        throw "Action1 URI map key 'U_Endpoint' is not defined."
    }

    $endpoint = & $Script:Action1_UriMap['U_Endpoint'] $orgId $EndpointId
    $path = "$Script:Action1_BaseURI{0}" -f $endpoint
    $target = "endpoint '$EndpointId'"

    if (-not $PSCmdlet.ShouldProcess($target, 'Update Action1 endpoint')) {
        Write-Action1Debug "Skipped updating endpoint '$EndpointId'."
        return
    }

    Write-Action1Debug "Updating endpoint '$EndpointId'."

    $response = Invoke-Action1ApiRequest `
        -Method PATCH `
        -Path $path `
        -Label "Update endpoint '$EndpointId'" `
        -Body $body

    if ($null -eq $response) {
        Write-Error ("Failed to update endpoint '{0}'." -f $EndpointId)
        return
    }

    Write-Action1Debug "Updated endpoint '$EndpointId'."

    $response
}
