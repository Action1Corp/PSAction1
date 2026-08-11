# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Resolve-Action1EndpointGroupById {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupId
    )

    Write-Action1Debug "Resolving endpoint group by ID '$GroupId'."
    $endpointGroups = @(Get-Action1EndpointGroups -ErrorAction Stop)

    $matchedGroups = @(
        $endpointGroups | Where-Object {
            $_.id -ieq $GroupId
        }
    )

    if ($matchedGroups.Count -eq 0) {
        Write-Error "Endpoint group with ID '$GroupId' was not found." -ErrorAction Stop
    }

    return $matchedGroups[0]
}

