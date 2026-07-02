# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Remove-Action1CompensatingControlRemediation {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^CVE-\d{4}-\d{3,6}$')]
        [string]$CVEId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RemediationId,

        [switch]$Force
    )

    if (Initialize-Action1DefaultOrg) {
        $orgId = Get-Action1DefaultOrgId
    }

    if (-not $Script:Action1_UriMap.ContainsKey('D_VulnerabilityRemediation')) {
        throw "Action1 URI map key 'D_VulnerabilityRemediation' is not defined."
    }

    $path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap['D_VulnerabilityRemediation'] $orgId $CVEId $RemediationId)
    $target = "CVE '$CVEId' remediation '$RemediationId'"

    if ($Force) {
        $ConfirmPreference = 'None'
    }

    if (-not $PSCmdlet.ShouldProcess($target, 'Delete Action1 vulnerability remediation')) {
        Write-Action1Debug "Skipped deleting remediation '$RemediationId' for vulnerability '$CVEId'."

        [pscustomobject]@{
            CVEId         = $CVEId
            RemediationId = $RemediationId
            Status        = 'Skipped'
            Response      = $null
        }
        return
    }

    Write-Action1Debug "Deleting remediation '$RemediationId' for vulnerability '$CVEId'."

    $response = Invoke-Action1ApiRequest -Method DELETE -Path $path -Label "Delete compensating control remediation '$RemediationId'"

    if ($null -eq $response) {
        Write-Error ("Failed to delete remediation '{0}' for vulnerability '{1}'." -f $RemediationId, $CVEId)

        [pscustomobject]@{
            CVEId         = $CVEId
            RemediationId = $RemediationId
            Status        = 'Failed'
            Response      = $null
        }
        return
    }

    Write-Action1Debug "Deleted remediation '$RemediationId' for vulnerability '$CVEId'."

    [pscustomobject]@{
        CVEId         = $CVEId
        RemediationId = $RemediationId
        Status        = 'Removed'
        Response      = $response
    }
}
