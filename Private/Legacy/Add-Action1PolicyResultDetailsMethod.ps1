# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Add-Action1PolicyResultDetailsMethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$InputObject
    )

    begin {
        $GetDetailsScriptBlock = {
            Invoke-Action1PagedGetRequest -Path $this.details -Label 'PolicyResultsDetails'
        }
    }
    process {
        $InputObject | Add-Member -MemberType ScriptMethod -Name 'GetDetails' -Value $GetDetailsScriptBlock -Force
        $InputObject
    }
}