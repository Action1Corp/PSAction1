# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function New-Action1AutomationScheduleDefinition {
    [CmdletBinding(DefaultParameterSetName = 'Create', PositionalBinding = $false)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Create')]
        [Parameter(ParameterSetName = 'FromSchedule')]
        [ValidateScript({ -not [string]::IsNullOrWhiteSpace($_) })]
        [string]$Name,

        [Parameter(Mandatory = $true, ParameterSetName = 'Create')]
        [Parameter(ParameterSetName = 'FromSchedule')]
        [ValidateNotNullOrEmpty()]
        [object[]]$Actions,

        [Parameter(Mandatory = $true, ParameterSetName = 'Create')]
        [Parameter(ParameterSetName = 'FromSchedule')]
        [AllowEmptyCollection()]
        [ValidateNotNull()]
        [object[]]$Endpoints,

        [Parameter(Mandatory = $true, ParameterSetName = 'Create')]
        [Parameter(ParameterSetName = 'FromSchedule')]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$RetryMinutes,

        [Parameter(Mandatory = $true, ParameterSetName = 'Create')]
        [Parameter(ParameterSetName = 'FromSchedule')]
        [ValidateScript({ -not [string]::IsNullOrWhiteSpace($_) })]
        [string]$Settings,

        [ValidateScript({ -not [string]::IsNullOrWhiteSpace($_) })]
        [string]$SettingsTimezone = 'UTC',

        [ValidateSet('Auto', '3.0', '4.0')]
        [string]$ApiVersion = 'Auto',

        [ValidateScript({ Test-Guid -Guid $_ -Label 'OrganizationId' })]
        [string]$OrganizationId,

        [ValidateScript({ Test-Guid -Guid $_ -Label 'ConfigurationId' })]
        [string]$ConfigurationId,

        [Parameter(Mandatory = $true, ParameterSetName = 'FromSchedule')]
        [Alias('ExistingAutomation')]
        [ValidateNotNull()]
        [object]$ExistingSchedule
    )

    $version = Resolve-Action1AutomationApiVersion -ApiVersion $ApiVersion
    if ($version -eq '3.0') {
        foreach ($parameterName in @('OrganizationId', 'ConfigurationId')) {
            if ($PSBoundParameters.ContainsKey($parameterName)) {
                throw "$parameterName applies only to API 4.0 automation definitions."
            }
        }
    }

    $fromExisting = $PSCmdlet.ParameterSetName -eq 'FromSchedule'
    if ($fromExisting) {
        $existing = ConvertFrom-Action1AutomationDefinition -InputObject $ExistingSchedule `
            -ApiVersion $version
        $config = $existing.Configuration
        $targets = $existing.Endpoints
    }
    else {
        $template = Get-Action1AutomationTemplate -Name Schedule -ApiVersion $version
        $config = $template
        if ($version -eq '4.0') {
            $config = $template.configuration
            if (-not $PSBoundParameters.ContainsKey('OrganizationId')) {
                $OrganizationId = Get-Action1DefaultOrgId
            }
            $null = Test-Guid -Guid $OrganizationId -Label 'OrganizationId'
            if (-not $PSBoundParameters.ContainsKey('ConfigurationId')) {
                $ConfigurationId = (New-Guid).Guid
            }
            $config.id = $ConfigurationId
            $config.organization_id = $OrganizationId
        }
        else {
            $config.PSObject.Properties.Remove('endpoints')
        }
        $config.settings_timezone = $SettingsTimezone
        $targets = @($Endpoints)
    }

    $propertyMap = [ordered]@{
        Name             = 'name'
        Actions          = 'actions'
        RetryMinutes     = 'retry_minutes'
        Settings         = 'settings'
        SettingsTimezone = 'settings_timezone'
        OrganizationId   = 'organization_id'
        ConfigurationId  = 'id'
    }
    foreach ($parameterName in $propertyMap.Keys) {
        if ($PSBoundParameters.ContainsKey($parameterName)) {
            $value = $PSBoundParameters[$parameterName]
            if ($parameterName -eq 'RetryMinutes') {
                $value = [string]$value
            }
            $config | Add-Member -NotePropertyName $propertyMap[$parameterName] `
                -NotePropertyValue $value -Force
        }
    }
    if ($PSBoundParameters.ContainsKey('Endpoints')) {
        $targets = @($Endpoints)
    }
    if ($null -eq $targets) {
        throw 'The existing automation has no endpoints. Specify Endpoints explicitly.'
    }
    if ($fromExisting -and ($null -eq $config.actions -or @($config.actions).Count -eq 0)) {
        throw 'The existing automation has no usable actions. Specify Actions explicitly.'
    }

    ConvertTo-Action1AutomationRequestBody -Configuration $config `
        -Endpoints $targets -ApiVersion $version -Operation Schedule `
        -PreserveIdentity:$fromExisting
}
