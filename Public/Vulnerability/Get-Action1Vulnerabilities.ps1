# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Get-Action1Vulnerabilities {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('Overdue', 'Due_soon', 'Overdue_due_soon', 'Due_later', 'Control_applied', 'All_except_control_applied', 'All')]
        [string]$RemediationStatus = 'Control_applied',
        [Parameter(Mandatory = $false)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'All')]
        [string]$Score = 'Critical'
    )

    if (Initialize-Action1DefaultOrg) {
        $orgId = Get-Action1DefaultOrgId
    }

    $uriPathBuilder = Get-UriMapValue -Key 'G_Vulnerabilities'

    $uri = & $uriPathBuilder $orgId
    $path = "$Script:Action1_BaseURI{0}" -f $uri
    $addArgs = $null

    if ($RemediationStatus -ne 'All'){
        $encodedStatus = [System.Uri]::EscapeDataString($RemediationStatus)
        $addArgs = Join-QueryString -QueryString $addArgs -Argument "remediation_status=$encodedStatus"
    }

    if ($Score -ne 'All'){
        $addArgs = Join-QueryString -QueryString $addArgs -Argument "score=$Score"
    }

    Write-Action1Debug "Listing vulnerabilities with remediation status '$RemediationStatus' and score '$Score'."

    Invoke-Action1PagedGetRequest -Path $path -Label 'Vulnerabilities' -AddArgs $addArgs
}
