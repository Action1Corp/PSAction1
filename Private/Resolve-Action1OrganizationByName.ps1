# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Resolve-Action1OrganizationByName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Org_Name
    )

    Write-Action1Debug "Resolving organization by name '$Org_Name'."
    $organizations = @(Get-Action1Organizations -ErrorAction Stop)

    $matchedOrgs = @(
        $organizations | Where-Object {
            $_.Org_Name -ieq $Org_Name
        }
    )

    if ($matchedOrgs.Count -eq 0) {
        Write-Error "Organization with name '$Org_Name' was not found." -ErrorAction Stop
    }

    if ($matchedOrgs.Count -gt 1) {
        $matchDetails = ($matchedOrgs | ForEach-Object {
            "$($_.Org_Name) [$($_.Org_ID)]"
        }) -join ', '

        Write-Error "Organization name '$Org_Name' is not unique. Matching organizations: $matchDetails. Use -Org_ID with the exact organization ID." -ErrorAction Stop
    }

    return $matchedOrgs[0]
}
