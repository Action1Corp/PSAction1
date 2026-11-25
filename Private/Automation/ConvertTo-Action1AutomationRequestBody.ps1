# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function ConvertTo-Action1AutomationRequestBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [object]$Configuration,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [ValidateNotNull()]
        [object[]]$Endpoints,

        [Parameter(Mandatory = $true)]
        [ValidateSet('3.0', '4.0')]
        [string]$ApiVersion,

        [Parameter(Mandatory = $true)]
        [ValidateSet('RunNow', 'Schedule')]
        [string]$Operation,

        [switch]$PreserveIdentity
    )

    $null = Test-Action1AutomationDefinition -Configuration $Configuration `
        -Endpoints $Endpoints -Operation $Operation
    $config = [pscustomobject]$Configuration
    $config.retry_minutes = [string]$config.retry_minutes

    $body = Get-Action1AutomationTemplate -Name $Operation -ApiVersion $ApiVersion
    if ($ApiVersion -eq '4.0') {
        $null = Test-Guid -Guid $config.id -Label 'ConfigurationId'
        $null = Test-Guid -Guid $config.organization_id -Label 'OrganizationId'
        if ($config.type -cne 'AutomationScheduleConfiguration') {
            throw 'Configuration type must be AutomationScheduleConfiguration.'
        }
        if (-not $PreserveIdentity) {
            $config.actions = @(foreach ($action in $config.actions) {
                $actionObject = [pscustomobject]$action
                if ($actionObject.PSObject.Properties.Name -contains 'id') {
                    $action
                }
                else {
                    # Add identity without changing the supplied action.
                    $actionProperties = [ordered]@{}
                    foreach ($property in $actionObject.PSObject.Properties) {
                        $actionProperties[$property.Name] = $property.Value
                    }
                    $actionProperties['id'] = (New-Guid).Guid
                    [pscustomobject]$actionProperties
                }
            })
        }
        if ($config.PSObject.Properties.Name -contains 'start_time') {
            $startTime = [datetime]::MinValue
            $validTime = [datetime]::TryParseExact(
                [string]$config.start_time, $Script:Action1_ApiTimestampTemplate,
                [cultureinfo]::InvariantCulture, [Globalization.DateTimeStyles]::None,
                [ref]$startTime
            )
            if (-not $validTime) {
                throw 'StartTime must use yyyy-MM-dd_HH-mm-ss format.'
            }
        }
        # Signatures are attached only after all configuration changes are complete.
        $body.configuration = $config
    }
    else {
        foreach ($property in $config.PSObject.Properties) {
            $body | Add-Member -NotePropertyName $property.Name `
                -NotePropertyValue $property.Value -Force
        }
    }
    $body.endpoints = @($Endpoints)
    Write-Action1Debug "Built unsigned API $ApiVersion $Operation automation body."
    return $body
}
