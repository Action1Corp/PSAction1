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
            $ParsedGuid = [guid]::Empty
            [guid]::TryParseExact($_, 'D', [ref]$ParsedGuid)
        })]
        [string]$EndpointId,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Comment
    )

    $Body = @{}

    if ($PSBoundParameters.ContainsKey('Name')) {
        $Body.name = $Name
    }

    if ($PSBoundParameters.ContainsKey('Comment')) {
        $Body.comment = $Comment
    }

    if ($Body.Count -eq 0) {
        Write-Error "Specify at least one value to update: -Name or -Comment."
        return
    }

    if (Initialize-Action1DefaultOrg) {
        $Org_ID = Get-Action1DefaultOrgId
    }

    if (-not $Script:Action1_UriMap.ContainsKey('U_Endpoint')) {
        throw "Action1 URI map key 'U_Endpoint' is not defined."
    }

    $Endpoint = & $Script:Action1_UriMap['U_Endpoint'] $Org_ID $EndpointId
    $Path = "$Script:Action1_BaseURI{0}" -f $Endpoint
    $Target = "endpoint '$EndpointId'"

    if (-not $PSCmdlet.ShouldProcess($Target, 'Update Action1 endpoint')) {
        Write-Action1Debug "Skipped updating endpoint '$EndpointId'."
        return
    }

    Write-Action1Debug "Updating endpoint '$EndpointId'."

    $Response = Invoke-Action1ApiRequest `
        -Method PATCH `
        -Path $Path `
        -Label "Update endpoint '$EndpointId'" `
        -Body $Body

    if ($null -eq $Response) {
        Write-Error ("Failed to update endpoint '{0}'." -f $EndpointId)
        return
    }

    Write-Action1Debug "Updated endpoint '$EndpointId'."

    $Response
}
