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
        [string]$CVEId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RemediationId,

        [switch]$Force
    )

    Initialize-Action1DefaultOrg
    $Org_ID = Get-Action1DefaultOrgId

    if (-not $Script:Action1_UriMap.ContainsKey('D_VulnerabilityRemediation')) {
        throw "Action1 URI map key 'D_VulnerabilityRemediation' is not defined."
    }

    $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap['D_VulnerabilityRemediation'] $Org_ID $CVEId $RemediationId)
    $Target = "CVE '$CVEId' remediation '$RemediationId'"

    if ($Force) {
        $ConfirmPreference = 'None'
    }

    if (-not $PSCmdlet.ShouldProcess($Target, 'Delete Action1 vulnerability remediation')) {
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

    $Response = Invoke-Action1ApiRequest -Method DELETE -Path $Path -Label "Delete compensating control remediation '$RemediationId'"

    if ($null -eq $Response) {
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
        Response      = $Response
    }
}
