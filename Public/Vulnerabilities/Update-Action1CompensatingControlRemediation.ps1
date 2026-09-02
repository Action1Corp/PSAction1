# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Update-Action1CompensatingControlRemediation {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^CVE-\d{4}-\d{4,}$')]
        [string]$CVEId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RemediationId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Comment
    )

    if (Initialize-Action1DefaultOrg) {
        $orgId = Get-Action1DefaultOrgId
    }

    $uriPathBuilder = Get-UriMapValue -Key 'U_VulnerabilityRemediation'

    $uri = & $uriPathBuilder $orgId $CVEId $RemediationId
    $path = "$Script:Action1_BaseURI{0}" -f $uri
    $target = "CVE '$CVEId' remediation '$RemediationId'"

    if (-not $PSCmdlet.ShouldProcess($target, 'Update Action1 compensating control remediation')) {
        Write-Action1Debug "Skipped updating remediation '$RemediationId' for vulnerability '$CVEId'."
        return
    }

    $body = @{
        comment = $Comment
    }

    Write-Action1Debug "Updating remediation '$RemediationId' for vulnerability '$CVEId'."

    $response = Invoke-Action1ApiRequest  -Method PATCH -Path $path -Label "Update compensating control remediation '$RemediationId'" -Body $body

    if ($null -eq $response) {
        Write-Error ("Failed to update remediation '{0}' for vulnerability '{1}'." -f $RemediationId, $CVEId)
        return
    }

    Write-Action1Debug "Updated remediation '$RemediationId' for vulnerability '$CVEId'."

    $response
}
