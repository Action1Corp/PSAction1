# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Add-Action1EndpointGroupMembers {
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

    $uriPathBuilder = Get-UriMapValue -Key 'N_EndpointGroupMembers'

    $uri = & $uriPathBuilder $orgId $resolvedGroupId
    $path = "$Script:Action1_BaseURI{0}" -f $uri
    $endpointCount = $endpointIdValues.Count
    $groupLabel = "endpoint group '$resolvedGroupId'"

    $body = @(
        foreach ($endpointIdValue in $endpointIdValues) {
            [ordered]@{
                method = 'POST'
                data   = [ordered]@{
                    endpoint_id = $endpointIdValue
                    type        = 'Endpoint'
                }
            }
        }
    )

    if ($Force) {
        $ConfirmPreference = 'None'
    }

    if (-not $PSCmdlet.ShouldProcess($groupLabel, "Add $endpointCount endpoints")) {
        Write-Action1Debug "Skipped adding $endpointCount endpoints to $groupLabel."
        return
    }

    Write-Action1Debug "Adding $endpointCount endpoints to $groupLabel."

    $response = Invoke-Action1ApiRequest `
        -Method POST `
        -Path $path `
        -Label "Add endpoints to $groupLabel" `
        -Body $body

    if ($null -eq $response) {
        Write-Error "Failed to add $endpointCount endpoints to $groupLabel."
        return
    }

    Write-Action1Debug "Added $endpointCount endpoints to $groupLabel."

    $response
}
