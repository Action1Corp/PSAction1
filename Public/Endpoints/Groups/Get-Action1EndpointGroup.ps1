# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1EndpointGroup {
    [CmdletBinding(DefaultParameterSetName = 'ByGroupId')]
    param(
        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'ByGroupId',
            Position = 0
        )]
        [ValidateNotNullOrEmpty()]
        [string]$GroupId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByGroupName')]
        [ValidateNotNullOrEmpty()]
        [string]$GroupName
    )

    if (Initialize-Action1DefaultOrg) {
        $orgId = Get-Action1DefaultOrgId
    }

    if ($PSCmdlet.ParameterSetName -eq 'ByGroupName') {
        $endpointGroup = Resolve-Action1EndpointGroupByName -GroupName $GroupName
    }
    else {
        $endpointGroup = Resolve-Action1EndpointGroupById -GroupId $GroupId
    }

    $resolvedGroupId = $endpointGroup.id

    $uriPathBuilder = Get-UriMapValue -Key 'G_EndpointGroup'

    $uri = & $uriPathBuilder $orgId $resolvedGroupId
    $path = "$Script:Action1_BaseURI{0}" -f $uri

    Write-Action1Debug "Getting endpoint group '$resolvedGroupId'."

    Invoke-Action1ApiRequest `
        -Method GET `
        -Path $path `
        -Label "Endpoint group '$resolvedGroupId'"
}
