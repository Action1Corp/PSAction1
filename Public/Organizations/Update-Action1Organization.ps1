# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Update-Action1Organization {
    [CmdletBinding(
        SupportsShouldProcess = $true,
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

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) {
                throw 'Name cannot contain empty or whitespace-only values.'
            }

            $true
        })]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) {
                throw 'Description cannot contain empty or whitespace-only values.'
            }

            $true
        })]
        [string]$Description,

        [switch]$Force
    )

    begin {
        $body = @{}
        $canUpdate = $true

        if ($PSBoundParameters.ContainsKey('Name')) {
            $body.name = $Name
        }

        if ($PSBoundParameters.ContainsKey('Description')) {
            $body.description = $Description
        }

        if ($body.Count -eq 0) {
            Write-Error 'Specify at least one value to update: -Name or -Description.'
            $canUpdate = $false
        }

        if ($Force) {
            $ConfirmPreference = 'None'
        }
    }

    process {
        if (-not $canUpdate) {
            return
        }

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
            return
        }

        $uriPathBuilder = Get-UriMapValue -Key 'U_Organization'

        $uri = & $uriPathBuilder $organizationIdentity.Org_ID
        $path = "$Script:Action1_BaseURI{0}" -f $uri
        $organizationLabel = $organizationIdentity.OrgLabel

        if (-not $PSCmdlet.ShouldProcess($organizationLabel, 'Update organization')) {
            Write-Action1Debug "Skipped updating $organizationLabel."
            return
        }

        Write-Action1Debug "Updating $organizationLabel."

        $response = Invoke-Action1ApiRequest `
            -Method PATCH `
            -Path $path `
            -Label "Update $organizationLabel" `
            -Body $body

        if ($null -eq $response) {
            Write-Error "Failed to update $organizationLabel."
            return
        }

        Write-Action1Debug "Updated $organizationLabel."

        $response
    }
}
