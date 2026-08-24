# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Remove-Action1EndpointGroupMembers {
    [CmdletBinding(
        SupportsShouldProcess = $true,
        DefaultParameterSetName = 'ByGroupIdEndpointIds'
    )]
    param(
        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'ByGroupIdEndpointIds',
            Position = 0
        )]
        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'ByGroupIdEndpointObjects',
            Position = 0
        )]
        [ValidateNotNullOrEmpty()]
        [string]$GroupId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByGroupNameEndpointIds')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ByGroupNameEndpointObjects')]
        [ValidateNotNullOrEmpty()]
        [string]$GroupName,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByGroupIdEndpointIds')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ByGroupNameEndpointIds')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            Test-Guid -Guid $_ -Label 'Each EndpointIds value'
        })]
        [string[]]$EndpointIds,

        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'ByGroupIdEndpointObjects',
            ValueFromPipeline = $true
        )]
        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'ByGroupNameEndpointObjects',
            ValueFromPipeline = $true
        )]
        [AllowNull()]
        [object[]]$EndpointObjects,

        [switch]$Force
    )

    begin {
        $endpointIdValues = New-Object System.Collections.ArrayList

        if ($Force) {
            $ConfirmPreference = 'None'
        }
    }

    process {
        if ($PSCmdlet.ParameterSetName -like '*EndpointObjects') {
            foreach ($endpointObject in $EndpointObjects) {
                $endpointIdentity = Get-Action1EndpointIdentityFromObject `
                    -EndpointObject $endpointObject

                if (-not $endpointIdentity.IsValid) {
                    Write-Action1Debug $endpointIdentity.ErrorMessage
                    Write-Error $endpointIdentity.ErrorMessage
                    continue
                }

                [void]$endpointIdValues.Add($endpointIdentity.EndpointId)
            }
        }
        else {
            foreach ($endpointId in $EndpointIds) {
                [void]$endpointIdValues.Add($endpointId.Trim())
            }
        }
    }

    end {
        $endpointCount = $endpointIdValues.Count

        if ($endpointCount -eq 0) {
            Write-Error 'No valid endpoint IDs were supplied.'
            return
        }

        if (Initialize-Action1DefaultOrg) {
            $orgId = Get-Action1DefaultOrgId
        }

        if ($PSCmdlet.ParameterSetName -like 'ByGroupName*') {
            $endpointGroup = Resolve-Action1EndpointGroupByName -GroupName $GroupName
        }
        else {
            $endpointGroup = Resolve-Action1EndpointGroupById -GroupId $GroupId
        }

        $resolvedGroupId = $endpointGroup.id

        $uriPathBuilder = Get-UriMapValue -Key 'D_EndpointGroupMembers'

        $uri = & $uriPathBuilder $orgId $resolvedGroupId
        $path = "$Script:Action1_BaseURI{0}" -f $uri
        $groupLabel = "endpoint group '$resolvedGroupId'"

        $body = @(
            foreach ($endpointIdValue in $endpointIdValues) {
                [ordered]@{
                    method      = 'DELETE'
                    endpoint_id = $endpointIdValue
                }
            }
        )

        $operation = "Remove $endpointCount endpoints"

        if (-not $PSCmdlet.ShouldProcess($groupLabel, $operation)) {
            Write-Action1Debug (
                "Skipped removing $endpointCount endpoints from $groupLabel."
            )
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
}
