# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Remove-Action1EndpointGroup {
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High',
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

    if (-not $PSCmdlet.ShouldProcess($targetLabel, 'Delete endpoint group')) {
        Write-Action1Debug "Skipped deleting $targetLabel."

        [pscustomobject]@{
            GroupId   = $GroupId
            GroupName = $GroupName
            Status    = 'Skipped'
            Response  = $null
        }
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
    $resolvedGroupName = $endpointGroup.name
    $groupLabel = "endpoint group '$resolvedGroupId'"

    $uriPathBuilder = Get-UriMapValue -Key 'D_EndpointGroup'

    $uri = & $uriPathBuilder $orgId $resolvedGroupId
    $path = "$Script:Action1_BaseURI{0}" -f $uri

    Write-Action1Debug "Deleting $groupLabel."

    $response = Invoke-Action1ApiRequest `
        -Method DELETE `
        -Path $path `
        -Label "Delete $groupLabel" `
        -RawResponse

    if ($null -eq $response) {
        Write-Error "Failed to delete $groupLabel."

        [pscustomobject]@{
            GroupId   = $resolvedGroupId
            GroupName = $resolvedGroupName
            Status    = 'Failed'
            Response  = $null
        }
        return
    }

    Write-Action1Debug "$groupLabel was deleted successfully."

    [pscustomobject]@{
        GroupId   = $resolvedGroupId
        GroupName = $resolvedGroupName
        Status    = 'Removed'
        Response  = $response
    }
}
