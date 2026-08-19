# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Update-Action1EndpointGroup {
    [CmdletBinding(
        SupportsShouldProcess = $true,
        DefaultParameterSetName = 'ByGroupId'
    )]
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
        [string]$GroupName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [object]$EndpointGroupDefinition,

        [switch]$Force
    )

    if ($Force) {
        $ConfirmPreference = 'None'
    }

    if ($PSCmdlet.ParameterSetName -eq 'ByGroupName') {
        $targetLabel = "endpoint group '$GroupName'"
    }
    else {
        $targetLabel = "endpoint group '$GroupId'"
    }

    if (-not $PSCmdlet.ShouldProcess($targetLabel, 'Update endpoint group')) {
        Write-Action1Debug "Skipped updating $targetLabel."
        return
    }

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

    $uriPathBuilder = Get-UriMapValue -Key 'U_EndpointGroup'

    $uri = & $uriPathBuilder $orgId $resolvedGroupId
    $path = "$Script:Action1_BaseURI{0}" -f $uri
    $groupLabel = "endpoint group '$resolvedGroupId'"

    Write-Action1Debug "Updating $groupLabel."

    $response = Invoke-Action1ApiRequest `
        -Method PATCH `
        -Path $path `
        -Label "Update $groupLabel" `
        -Body $EndpointGroupDefinition

    if ($null -eq $response) {
        Write-Error "Failed to update $groupLabel."
        return
    }

    Write-Action1Debug "Updated $groupLabel."

    $response
}
