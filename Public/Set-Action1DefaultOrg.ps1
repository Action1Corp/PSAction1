# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Set-Action1DefaultOrg {
    [CmdletBinding(DefaultParameterSetName = 'ById')]
    param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = 'ById'
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('OrgId')]
        [string]$Org_ID,

        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'ByName'
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('OrgName')]
        [string]$Org_Name
    )

    switch ($PSCmdlet.ParameterSetName) {
        'ById' {
            $Script:Action1_Default_Org = $Org_ID
        }

        'ByName' {
            $organization = Resolve-Action1OrganizationByName -Org_Name $Org_Name
            $Script:Action1_Default_Org = $organization.id
        }
    }
}