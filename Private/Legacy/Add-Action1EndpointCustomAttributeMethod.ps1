# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Add-Action1EndpointCustomAttributeMethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$InputObject
    )

    begin {
        $GetCustomAttributeScriptBlock = {
            param(
                [Parameter(Mandatory)]
                [string]$Name
            )
            ($this.custom | Where-Object { $_.name -eq $Name }).value
        }
    }
    process {
        $InputObject | Add-Member -MemberType ScriptMethod -Name 'GetCustomAttribute' -Value $GetCustomAttributeScriptBlock -Force
        $InputObject
    }
}