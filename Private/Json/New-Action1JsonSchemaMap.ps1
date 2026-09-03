# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function New-Action1JsonSchemaMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) {
                throw 'JSON schema cannot be empty.'
            }

            $true
        })]
        [string]$Schema,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) {
                throw 'JSON object type cannot be empty.'
            }

            $true
        })]
        [string]$Type
    )

    New-Action1JsonHeader `
        -HeaderTemplate $Script:Action1_ExportJsonHeader `
        -PropertyValues ([ordered]@{
            schema        = ([string]$Schema).Trim()
            datetime      = $null
            region        = $null
            enterprise_id = $null
            type          = ([string]$Type).Trim()
            items         = $null
        })
}
