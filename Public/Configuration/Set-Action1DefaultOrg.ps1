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
            Write-Action1Debug "Resolving default organization by ID '$Org_ID'."
            $organization = Resolve-Action1OrganizationById -Org_ID $Org_ID
            $Script:Action1_Default_Org_Id = $organization.Org_ID
            $Script:Action1_Default_Org_Name = $organization.Org_Name
        }

        'ByName' {
            Write-Action1Debug "Resolving default organization by name '$Org_Name'."
            $organization = Resolve-Action1OrganizationByName -Org_Name $Org_Name
            $Script:Action1_Default_Org_Id = $organization.Org_ID
            $Script:Action1_Default_Org_Name = $organization.Org_Name
        }
    }

    Write-Action1Debug "Default organization set to '$Script:Action1_Default_Org_Name'."
}
