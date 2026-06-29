function Update-Action1CompensatingControlRemediation {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^CVE-\d{4}-\d{3,6}$')]
        [string]$CVEId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RemediationId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Comment
    )

    Initialize-Action1DefaultOrg
    $Org_ID = Get-Action1DefaultOrgId

    if (-not $Script:Action1_UriMap.ContainsKey('U_VulnerabilityRemediation')) {
        throw "Action1 URI map key 'U_VulnerabilityRemediation' is not defined."
    }

    $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap['U_VulnerabilityRemediation'] $Org_ID $CVEId $RemediationId)
    $Target = "CVE '$CVEId' remediation '$RemediationId'"

    if (-not $PSCmdlet.ShouldProcess($Target, 'Update Action1 compensating control remediation')) {
        Write-Action1Debug "Skipped updating remediation '$RemediationId' for vulnerability '$CVEId'."
        return
    }

    $Body = @{
        comment = $Comment
    }

    Write-Action1Debug "Updating remediation '$RemediationId' for vulnerability '$CVEId'."

    $Response = Invoke-Action1ApiRequest  -Method PATCH -Path $Path -Label "Update compensating control remediation '$RemediationId'" -Body $Body

    if ($null -eq $Response) {
        Write-Error ("Failed to update remediation '{0}' for vulnerability '{1}'." -f $RemediationId, $CVEId)
        return
    }

    Write-Action1Debug "Updated remediation '$RemediationId' for vulnerability '$CVEId'."

    $Response
}
