# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Resolve-Action1OrganizationById {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Org_ID
    )

    Write-Action1Debug "Resolving organization by ID '$Org_ID'."
    $organizations = @(Get-Action1Organizations -ErrorAction Stop)

    $matchedOrgs = @(
        $organizations | Where-Object {
            $_.Org_ID -ieq $Org_ID
        }
    )

    if ($matchedOrgs.Count -eq 0) {
        Write-Error "Organization with ID '$Org_ID' was not found." -ErrorAction Stop
    }

    return $matchedOrgs[0]
}
