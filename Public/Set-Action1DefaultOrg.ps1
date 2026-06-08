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