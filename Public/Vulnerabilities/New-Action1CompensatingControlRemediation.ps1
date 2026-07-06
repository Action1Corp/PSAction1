# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function New-Action1CompensatingControlRemediation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidatePattern('^CVE-\d{4}-\d{3,6}$')]
        [string]$CVEId,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) {
                throw 'Comment cannot contain empty or whitespace-only values.'
            }

            $true
        })]
        [string]$Comment,

        [Parameter(Mandatory = $true, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) {
                throw 'ProductName cannot contain empty or whitespace-only values.'
            }

            $true
        })]
        [string]$ProductName
    )

    if (Initialize-Action1DefaultOrg) {
        $orgId = Get-Action1DefaultOrgId
    }

    $uriPathBuilder = Get-UriMapValue -Key 'N_VulnerabilityRemediation'

    $uri = & $uriPathBuilder $orgId $CVEId
    $path = "$Script:Action1_BaseURI{0}" -f $uri

    $body = @{
        comment      = $Comment
        product_name = $ProductName
    }

    Write-Action1Debug ("Creating compensating control remediation for vulnerability '{0}'." -f $CVEId)

    $response = Invoke-Action1ApiRequest  -Method POST -Path $path -Label "Create compensating control remediation '$CVEId'" -Body $body

    if ($null -eq $response) {
        Write-Error ("Failed to create compensating control remediation for vulnerability '{0}'." -f $CVEId)
        return
    }

    Write-Action1Debug ("Created compensating control remediation for vulnerability '{0}'." -f $CVEId)

    $response
}
