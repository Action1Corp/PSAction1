# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Resolve-Action1EndpointGroupByName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupName
    )

    Write-Action1Debug "Resolving endpoint group by name '$GroupName'."
    $endpointGroups = @(Get-Action1EndpointGroups -ErrorAction Stop)

    $matchedGroups = @(
        $endpointGroups | Where-Object {
            $_.name -ieq $GroupName
        }
    )

    if ($matchedGroups.Count -eq 0) {
        Write-Error "Endpoint group with name '$GroupName' was not found." -ErrorAction Stop
    }

    if ($matchedGroups.Count -gt 1) {
        $matchDetails = ($matchedGroups | ForEach-Object {
            "$($_.name) [$($_.id)]"
        }) -join ', '

        Write-Error "Endpoint group name '$GroupName' is not unique. Matching endpoint groups: $matchDetails. Use -GroupId with the exact endpoint group ID." -ErrorAction Stop
    }

    return $matchedGroups[0]
}

