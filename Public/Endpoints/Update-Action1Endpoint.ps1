# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Update-Action1Endpoint {
    [CmdletBinding(
        SupportsShouldProcess = $true,
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

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Comment,

        [switch]$Force
    )

    begin {
        $body = @{}
        $canUpdate = $true

        if ($PSBoundParameters.ContainsKey('Name')) {
            $body.name = $Name
        }

        if ($PSBoundParameters.ContainsKey('Comment')) {
            $body.comment = $Comment
        }

        if ($body.Count -eq 0) {
            Write-Error "Specify at least one value to update: -Name or -Comment."
            $canUpdate = $false
        }

        if ($Force) {
            $ConfirmPreference = 'None'
        }
    }

    process {
        if (-not $canUpdate) {
            return
        }

        if ($PSCmdlet.ParameterSetName -eq 'ByEndpointObject') {
            $target = ConvertTo-Action1EndpointTarget -EndpointObject $EndpointObject
        }
        else {
            $target = ConvertTo-Action1EndpointTarget -EndpointId $EndpointId
        }

        if (-not $target.IsValid) {
            Write-Action1Debug $target.ErrorMessage
            Write-Error $target.ErrorMessage
        }
        else {
            if (Initialize-Action1DefaultOrg) {
                $orgId = Get-Action1DefaultOrgId
            }

            $uriPathBuilder = Get-UriMapValue -Key 'U_Endpoint'

            $uri = & $uriPathBuilder $orgId $target.EndpointId
            $path = "$Script:Action1_BaseURI{0}" -f $uri
            $endpointLabel = "endpoint with id '$($target.EndpointId)'"

            if ($null -ne $target.EndpointName) {
                $endpointLabel = "$endpointLabel and name '$($target.EndpointName)'"
            }

            if (-not $PSCmdlet.ShouldProcess($endpointLabel, 'Update endpoint')) {
                Write-Action1Debug "Skipped updating $endpointLabel."
            }
            else {
                Write-Action1Debug "Updating $endpointLabel."

                $response = Invoke-Action1ApiRequest `
                    -Method PATCH `
                    -Path $path `
                    -Label "Update $endpointLabel" `
                    -Body $body

                if ($null -eq $response) {
                    Write-Error "Failed to update $endpointLabel."
                }
                else {
                    Write-Action1Debug "Updated $endpointLabel."

                    $response
                }
            }
        }
    }
}
