# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Update-Action1Enterprise {
    [CmdletBinding(SupportsShouldProcess = $true, PositionalBinding = $false)]
    param(
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

        $uriPathBuilder = Get-UriMapValue -Key 'U_Enterprise'

        $uri = & $uriPathBuilder
        $path = "$Script:Action1_BaseURI{0}" -f $uri
        $enterpriseLabel = 'current enterprise settings'

        if (-not $PSCmdlet.ShouldProcess($enterpriseLabel, 'Update enterprise')) {
            Write-Action1Debug "Skipped updating $enterpriseLabel."
            return
        }

        Write-Action1Debug "Updating $enterpriseLabel."

        $response = Invoke-Action1ApiRequest `
            -Method PATCH `
            -Path $path `
            -Label "Update $enterpriseLabel" `
            -Body $body

        if ($null -eq $response) {
            Write-Error "Failed to update $enterpriseLabel."
            return
        }

        Write-Action1Debug "Updated $enterpriseLabel."

        $response
    }
}
