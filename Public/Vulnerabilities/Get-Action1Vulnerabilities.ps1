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

    Initialize-Action1DefaultOrg
    $Org_ID = Get-Action1DefaultOrgId

    if (-not $Script:Action1_UriMap.ContainsKey('G_Vulnerabilities')) {
        throw "Action1 URI map key 'G_Vulnerabilities' is not defined."
    }

    $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap['G_Vulnerabilities'] $Org_ID)
    $AddArgs = $null

    if ($RemediationStatus -ne 'All'){
        $EncodedStatus = [System.Uri]::EscapeDataString($RemediationStatus)
        $AddArgs = Join-QueryString -QueryString $AddArgs -Argument "remediation_status=$EncodedStatus"
    }

    if ($Score -ne 'All'){
        $AddArgs = Join-QueryString -QueryString $AddArgs -Argument "score=$Score"
    }

    Write-Action1Debug "Listing vulnerabilities with remediation status '$RemediationStatus' and score '$Score'."

    Invoke-Action1PagedGetRequest -Path $Path -Label 'Vulnerabilities' -AddArgs $AddArgs
}
