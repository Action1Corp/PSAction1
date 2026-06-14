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
        [ValidateSet('Due soon', 'Overdue', 'Due later', 'Control_applied')]
        [string]$RemediationStatus
    )

    $Org_ID = Initialize-Action1DefaultOrg

    if (-not $Script:Action1_UriMap.ContainsKey('G_Vulnerabilities')) {
        throw "Action1 URI map key 'G_Vulnerabilities' is not defined."
    }

    $Path = & $Script:Action1_UriMap['G_Vulnerabilities'] $Org_ID
    $AddArgs = $null

    if ($PSBoundParameters.ContainsKey('RemediationStatus') -and -not [string]::IsNullOrWhiteSpace($RemediationStatus)) {
        $EncodedStatus = [System.Uri]::EscapeDataString($RemediationStatus)
        $AddArgs = Join-QueryString -QueryString $AddArgs -Argument "remediation_status=$EncodedStatus"
        Write-Action1Debug "Listing vulnerabilities with remediation_status '$RemediationStatus'."
    }
    else {
        Write-Action1Debug 'Listing vulnerabilities without remediation status filter.'
    }

    Invoke-Action1PagedGetRequest -Path $Path -Label 'Vulnerabilities' -AddArgs $AddArgs
}
