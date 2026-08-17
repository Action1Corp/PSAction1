# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Get-Action1EndpointGroupMembers {
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
        [string]$GroupName,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Connected', 'Disconnected', 'Pending Uninstall', 'All')]
        [string]$Status = 'All',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Yes', 'No', 'All')]
        [string]$RebootRequired = 'All',

        [Parameter(Mandatory = $false)]
        [ValidateSet(
            'Windows 11',
            'Windows 10',
            'Windows Server',
            'macOS',
            'linux',
            'All'
        )]
        [string]$OS = 'All'
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

    $uriPathBuilder = Get-UriMapValue -Key 'G_EndpointGroupMembers'

    $uri = & $uriPathBuilder $orgId $resolvedGroupId
    $path = "$Script:Action1_BaseURI{0}" -f $uri
    $addArgs = $null
    $debugFilters = @()

    if ($Status -ne 'All') {
        $encodedStatus = [System.Uri]::EscapeDataString($Status)
        $queryArgument = "status=$encodedStatus"
        $addArgs = Join-QueryString -QueryString $addArgs -Argument $queryArgument
        $debugFilters += "status '$Status'"
    }

    if ($RebootRequired -ne 'All') {
        $encodedRebootRequired = [System.Uri]::EscapeDataString($RebootRequired)
        $queryArgument = "reboot_required=$encodedRebootRequired"
        $addArgs = Join-QueryString -QueryString $addArgs -Argument $queryArgument
        $debugFilters += "reboot required '$RebootRequired'"
    }

    if ($OS -ne 'All') {
        $encodedOS = [System.Uri]::EscapeDataString($OS)
        $queryArgument = "OS=$encodedOS"
        $addArgs = Join-QueryString -QueryString $addArgs -Argument $queryArgument
        $debugFilters += "OS '$OS'"
    }

    $debugMessage = "Listing endpoints in endpoint group '$resolvedGroupId'"

    if ($debugFilters.Count -gt 0) {
        $debugMessage = '{0} with {1}' -f $debugMessage, ($debugFilters -join ', ')
    }

    Write-Action1Debug "$debugMessage."

    Invoke-Action1PagedGetRequest `
        -Path $path `
        -Label "Endpoint group '$resolvedGroupId' endpoints" `
        -AddArgs $addArgs
}
