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