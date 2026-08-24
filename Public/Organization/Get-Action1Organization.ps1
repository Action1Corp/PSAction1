# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1Organization {
    [CmdletBinding(DefaultParameterSetName = 'ByOrgId')]
    param(
        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'ByOrgId',
            Position = 0
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            Test-Guid -Guid $_ -Label 'OrgID'
        })]
        [Alias('Org_ID')]
        [string]$OrgID,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByOrgName')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) {
                throw 'OrgName cannot contain empty or whitespace-only values.'
            }

            $true
        })]
        [Alias('Org_Name')]
        [string]$OrgName
    )

    process {
        if ($PSCmdlet.ParameterSetName -eq 'ByOrgName') {
            $organization = Resolve-Action1OrganizationByName -Org_Name $OrgName
            $organizationIdentity = New-Action1OrganizationIdentity `
                -Org_ID $organization.Org_ID `
                -Org_Name $organization.Org_Name
        }
        else {
            $organizationIdentity = New-Action1OrganizationIdentity -Org_ID $OrgID
        }

        if (-not $organizationIdentity.IsValid) {
            Write-Action1Debug $organizationIdentity.ErrorMessage
            Write-Error $organizationIdentity.ErrorMessage
            return
        }

        $uriPathBuilder = Get-UriMapValue -Key 'G_Organization'

        $uri = & $uriPathBuilder $organizationIdentity.Org_ID
        $path = "$Script:Action1_BaseURI{0}" -f $uri
        $organizationLabel = $organizationIdentity.OrgLabel

        Write-Action1Debug "Getting $organizationLabel."

        Invoke-Action1ApiRequest `
            -Method GET `
            -Path $path `
            -Label "Get $organizationLabel"
    }
}
