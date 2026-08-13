# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Remove-Action1EndpointGroupMembers {
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
        [ValidateScript({
            if (-not (Test-Guid $_)) {
                throw 'Each EndpointIds value must use the standard GUID format.'
            }

            $true
        })]
        [string[]]$EndpointIds,

        [switch]$Force
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
    $endpointIdValues = @(
        foreach ($endpointId in $EndpointIds) {
            $endpointId.Trim()
        }
    )

    $uriPathBuilder = Get-UriMapValue -Key 'D_EndpointGroupMembers'

    $uri = & $uriPathBuilder $orgId $resolvedGroupId
    $path = "$Script:Action1_BaseURI{0}" -f $uri
    $endpointCount = $endpointIdValues.Count
    $groupLabel = "endpoint group '$resolvedGroupId'"

    $body = @(
        foreach ($endpointIdValue in $endpointIdValues) {
            [ordered]@{
                method      = 'DELETE'
                endpoint_id = $endpointIdValue
            }
        }
    )

    if ($Force) {
        $ConfirmPreference = 'None'
    }

    if (-not $PSCmdlet.ShouldProcess($groupLabel, "Remove $endpointCount endpoints")) {
        Write-Action1Debug "Skipped removing $endpointCount endpoints from $groupLabel."
        return
    }

    Write-Action1Debug "Removing $endpointCount endpoints from $groupLabel."

    $response = Invoke-Action1ApiRequest `
        -Method POST `
        -Path $path `
        -Label "Remove endpoints from $groupLabel" `
        -Body $body

    if ($null -eq $response) {
        Write-Error "Failed to remove $endpointCount endpoints from $groupLabel."
        return
    }

    Write-Action1Debug "Removed $endpointCount endpoints from $groupLabel."

    $response
}
