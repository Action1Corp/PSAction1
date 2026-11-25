# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function New-Action1AutomationAction {
    [CmdletBinding(PositionalBinding = $false)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ -not [string]::IsNullOrWhiteSpace($_) })]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ -not [string]::IsNullOrWhiteSpace($_) })]
        [string]$TemplateId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [object]$Parameters,

        [ValidateScript({ -not [string]::IsNullOrWhiteSpace($_) })]
        [string]$ActionId = (New-Guid).Guid
    )

    if (
        $Parameters -isnot [System.Collections.IDictionary] -and
        $Parameters -isnot [PSCustomObject]
    ) {
        throw 'Parameters must be a dictionary or PSCustomObject, not a JSON string.'
    }
    $parameterObject = [pscustomobject]$Parameters
    $templateNames = @{
        run_script     = 'RunScript'
        deploy_update  = 'DeployUpdate'
        deploy_package = 'DeployPackage'
    }
    if ($templateNames.ContainsKey($TemplateId)) {
        $action = Get-Action1AutomationTemplate -Name $templateNames[$TemplateId]
    }
    else {
        # Custom action templates retain their supplied ID and parameter object.
        $action = [pscustomobject][ordered]@{
            name        = ''
            template_id = $TemplateId
            params      = [pscustomobject]@{}
        }
    }
    foreach ($property in $parameterObject.PSObject.Properties) {
        $action.params | Add-Member -NotePropertyName $property.Name `
            -NotePropertyValue $property.Value -Force
    }
    $action.name = $Name
    $action | Add-Member -NotePropertyName 'id' -NotePropertyValue $ActionId
    $null = Test-Action1AutomationAction -Action $action
    return $action
}
