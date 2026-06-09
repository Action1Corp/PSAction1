function Resolve-Action1OrganizationByName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Org_Name
    )

    $organizations = @(Get-Action1 -Query Organizations -ErrorAction Stop)

    $matchedOrgs = @(
        $organizations | Where-Object {
            $_.name -ieq $Org_Name
        }
    )

    if ($matchedOrgs.Count -eq 0) {
        Write-Error "Organization with name '$Org_Name' was not found." -ErrorAction Stop
    }

    if ($matchedOrgs.Count -gt 1) {
        $matchDetails = ($matchedOrgs | ForEach-Object {
            "$($_.name) [$($_.id)]"
        }) -join ', '

        Write-Error "Organization name '$Org_Name' is not unique. Matching organizations: $matchDetails. Use -Org_ID with the exact organization ID." -ErrorAction Stop
    }

    return $matchedOrgs[0]
}