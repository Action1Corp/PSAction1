# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function New-Action1Organization {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) {
                throw 'Name cannot contain empty or whitespace-only values.'
            }

            $true
        })]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Description = '',

        [switch]$Force
    )

    $organizationLabel = New-Action1OrganizationLabel -Org_Name $Name

    if ($Force) {
        $ConfirmPreference = 'None'
    }

    if (-not $PSCmdlet.ShouldProcess($organizationLabel, 'Create organization')) {
        Write-Action1Debug "Skipped creating $organizationLabel."
        return
    }

    $uriPathBuilder = Get-UriMapValue -Key 'N_Organization'

    $uri = & $uriPathBuilder
    $path = "$Script:Action1_BaseURI{0}" -f $uri

    $body = @{
        name        = $Name
        description = $Description
    }

    Write-Action1Debug "Creating $organizationLabel."

    $response = Invoke-Action1ApiRequest `
        -Method POST `
        -Path $path `
        -Label "Create $organizationLabel" `
        -Body $body

    if ($null -eq $response) {
        Write-Error "Failed to create $organizationLabel."
        return
    }

    Write-Action1Debug "Created $organizationLabel."

    $response
}
