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