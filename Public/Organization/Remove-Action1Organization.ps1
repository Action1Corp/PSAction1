# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Remove-Action1Organization {
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High',
        DefaultParameterSetName = 'ByOrgId'
    )]
    param(
        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'ByOrgId',
            Position = 0
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if (-not (Test-Guid $_)) {
                throw 'OrgID must use the standard GUID format.'
            }

            $true
        })]
        [Alias('Org_ID')]
        [string]$OrgID,

        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'ByOrganizationObject',
            ValueFromPipeline = $true
        )]
        [AllowNull()]
        [object]$OrganizationObject,

        [switch]$Force
    )

    process {
        if ($PSCmdlet.ParameterSetName -eq 'ByOrganizationObject') {
            $organizationIdentity = Get-Action1OrganizationIdentityFromObject `
                -OrganizationObject $OrganizationObject
        }
        else {
            $organizationIdentity = New-Action1OrganizationIdentity -Org_ID $OrgID
        }

        if (-not $organizationIdentity.IsValid) {
            Write-Action1Debug $organizationIdentity.ErrorMessage
            Write-Error $organizationIdentity.ErrorMessage

            [pscustomobject]@{
                Org_ID   = $organizationIdentity.Org_ID
                Org_Name = $organizationIdentity.Org_Name
                Status   = 'Invalid'
                Response = $null
            }
            return
        }

        $uriPathBuilder = Get-UriMapValue -Key 'D_Organization'

        $uri = & $uriPathBuilder $organizationIdentity.Org_ID
        $path = "$Script:Action1_BaseURI{0}" -f $uri
        $organizationLabel = $organizationIdentity.OrgLabel

        if ($Force) {
            $ConfirmPreference = 'None'
        }

        if (-not $PSCmdlet.ShouldProcess($organizationLabel, 'Delete organization')) {
            Write-Action1Debug "Skipped deleting $organizationLabel."

            [pscustomobject]@{
                Org_ID   = $organizationIdentity.Org_ID
                Org_Name = $organizationIdentity.Org_Name
                Status   = 'Skipped'
                Response = $null
            }
            return
        }

        Write-Action1Debug "Deleting $organizationLabel."

        $response = Invoke-Action1ApiRequest `
            -Method DELETE `
            -Path $path `
            -Label "Delete $organizationLabel" `
            -RawResponse

        if ($null -eq $response) {
            Write-Error "Failed to delete $organizationLabel."

            [pscustomobject]@{
                Org_ID   = $organizationIdentity.Org_ID
                Org_Name = $organizationIdentity.Org_Name
                Status   = 'Failed'
                Response = $null
            }
            return
        }

        Write-Action1Debug "$organizationLabel was deleted successfully."

        [pscustomobject]@{
            Org_ID   = $organizationIdentity.Org_ID
            Org_Name = $organizationIdentity.Org_Name
            Status   = 'Removed'
            Response = $response
        }
    }
}
