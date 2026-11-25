# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

# Windows PowerShell 5.1 / Pester 3.4 or later. All fixtures are synthetic.
$modulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'PSAction1.psd1'
Import-Module $modulePath -Force -ErrorAction Stop

InModuleScope PSAction1 {
    Describe 'Automation object builders' {
        BeforeEach {
            $script:Action1_BaseURI = ''
            $script:Action1_Default_Org_Id = '11111111-1111-1111-1111-111111111111'
            $script:Action1_DebugEnabled = $false
            $script:builderAction = New-Action1AutomationAction -Name 'Run script' `
                -TemplateId run_script -Parameters @{ run_script_id = 'synthetic_script' } `
                -ActionId 'existing_action'
            $script:builderTarget = New-Action1AutomationTarget -Id 'synthetic_group' `
                -Type EndpointGroup
            $script:builderParams = @{
                Name         = 'Synthetic automation'
                Actions      = @($script:builderAction)
                Endpoints    = @($script:builderTarget)
                RetryMinutes = 60
            }
            $script:existingFlat = [pscustomobject]@{
                id                = 'synthetic_schedule'
                type              = 'AutomationSchedule'
                self              = 'https://example.invalid/schedule'
                last_run          = '2026-01-01_12-00-00'
                next_run          = '2026-02-01_12-00-00'
                name              = 'Existing schedule'
                actions           = @($script:builderAction)
                endpoints         = @($script:builderTarget)
                retry_minutes     = '240'
                settings          = 'ENABLED MONTHLY:1 AT:12-00-00'
                settings_timezone = 'UTC'
                randomize_start   = '0'
            }
            $script:existingNested = [pscustomobject]@{
                id            = '22222222-2222-2222-2222-222222222222'
                type          = 'AutomationSchedule'
                configuration = [pscustomobject]@{
                    id                = '22222222-2222-2222-2222-222222222222'
                    type              = 'AutomationScheduleConfiguration'
                    organization_id   = $script:Action1_Default_Org_Id
                    name              = 'Existing schedule'
                    actions           = @($script:builderAction)
                    retry_minutes     = '240'
                    settings          = 'ENABLED MONTHLY:1 AT:12-00-00'
                    settings_timezone = 'UTC'
                    extension         = [pscustomobject]@{ values = @('preserve') }
                }
                endpoints     = @($script:builderTarget)
                signatures    = @(@{ object_signature = @{ value = 'stale' } })
            }
            Mock Invoke-Action1ApiRequest { throw 'Builders must not call the API.' }
            Mock Invoke-WebRequest { throw 'Tests must not call the network.' }
        }

        It 'builds a flat API 3 run-now body with singleton arrays and string minutes' {
            $body = New-Action1AutomationDefinition @builderParams -ApiVersion '3.0'
            $body.name | Should Be 'Synthetic automation'
            ($body.retry_minutes -is [string]) | Should Be $true
            ($body.actions -is [array]) | Should Be $true
            ($body.endpoints -is [array]) | Should Be $true
            $body.configuration | Should BeNullOrEmpty
            $body.signatures | Should BeNullOrEmpty
            $body.start_time | Should BeNullOrEmpty
            $body.endpoints.Count | Should Be 1
        }

        It 'builds API 4 run-now identity and converts an explicit time to UTC' {
            $body = New-Action1AutomationDefinition @builderParams -ApiVersion '4.0' `
                -ConfigurationId '33333333-3333-3333-3333-333333333333' `
                -StartTime ([DateTimeOffset]'2026-11-25T15:00:00+01:00')
            $body.configuration.id | Should Be '33333333-3333-3333-3333-333333333333'
            $body.configuration.type | Should Be 'AutomationScheduleConfiguration'
            $body.configuration.organization_id | Should Be $script:Action1_Default_Org_Id
            $body.configuration.start_time | Should Be '2026-11-25_14-00-00'
            $body.configuration.actions[0].id | Should Be 'existing_action'
            $body.name | Should BeNullOrEmpty
            $body.signatures | Should BeNullOrEmpty
        }

        It 'generates independent configuration IDs for new API 4 requests' {
            $first = New-Action1AutomationDefinition @builderParams -ApiVersion '4.0'
            $second = New-Action1AutomationDefinition @builderParams -ApiVersion '4.0'
            (Test-Guid $first.configuration.id) | Should Be $true
            ($first.configuration.id -ne $second.configuration.id) | Should Be $true
        }

        It 'resolves Auto from each supported URI version' {
            foreach ($version in @('3.0', '4.0')) {
                $script:Action1_BaseURI = "https://example.invalid/api/$version"
                $body = New-Action1AutomationDefinition @builderParams
                if ($version -eq '4.0') {
                    $body.configuration.name | Should Be 'Synthetic automation'
                }
                else {
                    $body.name | Should Be 'Synthetic automation'
                }
            }
        }

        It 'rejects Auto without a configured supported API version' {
            { New-Action1AutomationDefinition @builderParams } | Should Throw
            $script:Action1_BaseURI = 'https://example.invalid/api/5.0'
            { New-Action1AutomationDefinition @builderParams } | Should Throw
        }

        It 'does not change a constructed body when the active API changes' {
            $script:Action1_BaseURI = 'https://example.invalid/api/3.0'
            $body = New-Action1AutomationDefinition @builderParams
            $script:Action1_BaseURI = 'https://example.invalid/api/4.0'
            $body.name | Should Be 'Synthetic automation'
            $body.configuration | Should BeNullOrEmpty
        }

        It 'rejects explicit API 4 fields on API 3' {
            {
                New-Action1AutomationDefinition @builderParams -ApiVersion '3.0' `
                    -StartTime ([DateTimeOffset]::UtcNow)
            } | Should Throw
            {
                New-Action1AutomationDefinition @builderParams -ApiVersion '3.0' `
                    -OrganizationId $script:Action1_Default_Org_Id
            } | Should Throw
            {
                New-Action1AutomationDefinition @builderParams -ApiVersion '3.0' `
                    -ConfigurationId '33333333-3333-3333-3333-333333333333'
            } | Should Throw
        }

        It 'requires an organization for API 4 but supports an explicit offline value' {
            $script:Action1_Default_Org_Id = ''
            { New-Action1AutomationDefinition @builderParams -ApiVersion '4.0' } |
                Should Throw
            $body = New-Action1AutomationDefinition @builderParams -ApiVersion '4.0' `
                -OrganizationId '11111111-1111-1111-1111-111111111111'
            $body.configuration.organization_id |
                Should Be '11111111-1111-1111-1111-111111111111'
        }

        It 'reuses supplied nested actions and targets' {
            $body = New-Action1AutomationDefinition @builderParams -ApiVersion '4.0'
            [object]::ReferenceEquals($body.configuration.actions[0], $builderAction) |
                Should Be $true
            [object]::ReferenceEquals($body.endpoints[0], $builderTarget) |
                Should Be $true
        }

        It 'rejects missing action structure, null members, and invalid retry values' {
            $builderParams.Actions = @(@{ name = 'Incomplete' })
            { New-Action1AutomationDefinition @builderParams -ApiVersion '3.0' } |
                Should Throw
            $builderParams.Actions = @($builderAction, $null)
            { New-Action1AutomationDefinition @builderParams -ApiVersion '3.0' } |
                Should Throw
            $builderParams.Actions = @($builderAction)
            $builderParams.Endpoints = @($null)
            { New-Action1AutomationDefinition @builderParams -ApiVersion '3.0' } |
                Should Throw
            $builderParams.Endpoints = @($builderTarget)
            $builderParams.RetryMinutes = 0
            { New-Action1AutomationDefinition @builderParams -ApiVersion '3.0' } |
                Should Throw
        }

        It 'rejects empty run-now targets and whitespace names' {
            $builderParams.Endpoints = @()
            { New-Action1AutomationDefinition @builderParams -ApiVersion '3.0' } |
                Should Throw
            $builderParams.Endpoints = @($builderTarget)
            $builderParams.Name = '  '
            { New-Action1AutomationDefinition @builderParams -ApiVersion '4.0' } |
                Should Throw
        }

        It 'retains nested parameter references and types without JSON conversion' {
            $parameters = @{
                nested = @{ values = @('one') }
                Count  = 'custom'
                token  = [guid]'44444444-4444-4444-4444-444444444444'
            }
            $action = New-Action1AutomationAction -Name Custom -TemplateId custom_template `
                -Parameters $parameters
            (Test-Guid $action.id) | Should Be $true
            $action.template_id | Should Be 'custom_template'
            $action.params.Count | Should Be 'custom'
            [object]::ReferenceEquals($action.params.nested, $parameters.nested) |
                Should Be $true
            ($action.params.token -is [guid]) | Should Be $true
        }

        It 'accepts dictionary actions and filters without overwriting existing IDs' {
            $filter = @{ name = 'update_types'; values = @('Security Updates'); operator = 'include' }
            $builderParams.Actions = @(@{
                id          = 'existing_dictionary_action'
                name        = 'Deploy updates'
                template_id = 'deploy_update'
                params      = @{ scope = 'MatchingFilters'; filters = @($filter) }
            })
            foreach ($version in @('3.0', '4.0')) {
                $body = New-Action1AutomationDefinition @builderParams -ApiVersion $version
                $config = $body
                if ($version -eq '4.0') { $config = $body.configuration }
                $config.actions[0].id | Should Be 'existing_dictionary_action'
                $config.actions[0].params.filters[0].values[0] | Should Be 'Security Updates'
            }
        }

        It 'supports dictionary schedule configurations and preserves scalar source fields' {
            $source = @{
                type = 'AutomationSchedule'
                configuration = [ordered]@{
                    id = '22222222-2222-2222-2222-222222222222'
                    type = 'AutomationScheduleConfiguration'
                    organization_id = $script:Action1_Default_Org_Id
                    name = 'Existing dictionary schedule'
                    actions = @($builderAction)
                    retry_minutes = '240'
                    settings = 'DISABLED'
                    settings_timezone = 'UTC'
                    extension = @{ values = @('preserve') }
                }
                endpoints = @()
            }
            $body = New-Action1AutomationScheduleDefinition -ExistingSchedule $source `
                -Name Renamed -ApiVersion '4.0'
            $body.configuration.name | Should Be 'Renamed'
            $source.configuration.name | Should Be 'Existing dictionary schedule'
            [object]::ReferenceEquals(
                $body.configuration.extension, $source.configuration.extension
            ) | Should Be $true
        }

        It 'rejects raw JSON or scalar action parameters' {
            {
                New-Action1AutomationAction -Name Test -TemplateId run_script `
                    -Parameters '{"run_script_id":"script"}'
            } | Should Throw
            {
                New-Action1AutomationAction -Name Test -TemplateId run_script -Parameters 42
            } | Should Throw
        }

        It 'constructs all three known action templates without approval or reboot defaults' {
            foreach ($templateId in @('run_script', 'deploy_update', 'deploy_package')) {
                $action = New-Action1AutomationAction -Name Test -TemplateId $templateId `
                    -Parameters @{}
                $action.template_id | Should Be $templateId
                $action.params.reboot_options | Should BeNullOrEmpty
                $action.params.automatic_approve_updates | Should BeNullOrEmpty
            }
        }

        It 'keeps filter values as an array and accepts future filter names' {
            $filter = New-Action1AutomationActionFilter -Name future_filter `
                -Values 'one' -Operator INCLUDE
            ($filter.values -is [array]) | Should Be $true
            $filter.operator | Should Be 'include'
            $filter.name | Should Be 'future_filter'
        }

        It 'rejects malformed filter values and operators' {
            { New-Action1AutomationActionFilter -Name test -Values @('') -Operator include } |
                Should Throw
            { New-Action1AutomationActionFilter -Name test -Values @() -Operator include } |
                Should Throw
            { New-Action1AutomationActionFilter -Name test -Values one -Operator equals } |
                Should Throw
            {
                New-Action1AutomationAction -Name Test -TemplateId deploy_update `
                    -Parameters @{ filters = @(@{name='test';values=@(42);operator='include'}) }
            } | Should Throw
        }

        It 'accepts group IDs and ALL but requires GUIDs for individual endpoints' {
            (New-Action1AutomationTarget -Id ALL -Type EndpointGroup).id | Should Be 'ALL'
            (New-Action1AutomationTarget -Id named_group -Type endpointgroup).type |
                Should Be 'EndpointGroup'
            { New-Action1AutomationTarget -Id ALL -Type Endpoint } | Should Throw
            { New-Action1AutomationTarget -Id ' ' -Type EndpointGroup } | Should Throw
        }

        It 'supports an explicitly empty disabled schedule in both versions' {
            $builderParams.Endpoints = @()
            foreach ($version in @('3.0', '4.0')) {
                $body = New-Action1AutomationScheduleDefinition @builderParams `
                    -Settings DISABLED -ApiVersion $version
                ($body.endpoints -is [array]) | Should Be $true
                $body.endpoints.Count | Should Be 0
                $body.signatures | Should BeNullOrEmpty
                if ($version -eq '4.0') {
                    $body.configuration.settings_timezone | Should Be 'UTC'
                    $body.configuration.start_time | Should BeNullOrEmpty
                }
                else {
                    $body.settings_timezone | Should Be 'UTC'
                }
            }
        }

        It 'rejects enabled schedules with no targets' {
            $builderParams.Endpoints = @()
            {
                New-Action1AutomationScheduleDefinition @builderParams `
                    -Settings 'ENABLED ONCE AT:12-00-00 DATE:2026-01-01' -ApiVersion '3.0'
            } | Should Throw
        }

        It 'preserves unmodified v3 fields and excludes response metadata on update' {
            $body = New-Action1AutomationScheduleDefinition -ExistingSchedule $existingFlat `
                -RetryMinutes 120 -ApiVersion '3.0'
            $body.retry_minutes | Should Be '120'
            $body.settings | Should Be $existingFlat.settings
            $body.name | Should Be $existingFlat.name
            $body.randomize_start | Should Be '0'
            $body.id | Should Be $existingFlat.id
            $body.type | Should BeNullOrEmpty
            $body.self | Should BeNullOrEmpty
            $body.last_run | Should BeNullOrEmpty
            $body.next_run | Should BeNullOrEmpty
            $existingFlat.retry_minutes | Should Be '240'
        }

        It 'preserves v4 identity, action IDs and extension fields but omits signatures' {
            $body = New-Action1AutomationScheduleDefinition -ExistingSchedule $existingNested `
                -Name Renamed -ApiVersion '4.0'
            $body.configuration.id | Should Be $existingNested.configuration.id
            $body.configuration.actions[0].id | Should Be 'existing_action'
            $body.configuration.retry_minutes | Should Be '240'
            $body.configuration.extension.values[0] | Should Be 'preserve'
            $body.configuration.name | Should Be 'Renamed'
            $body.signatures | Should BeNullOrEmpty
            $existingNested.signatures[0].object_signature.value | Should Be 'stale'
            $existingNested.configuration.name | Should Be 'Existing schedule'
        }

        It 'retains a nondefault timezone unless explicitly overridden on update' {
            $existingNested.configuration.settings_timezone = 'Europe/Warsaw'
            $body = New-Action1AutomationScheduleDefinition -ExistingSchedule $existingNested `
                -RetryMinutes 30 -ApiVersion '4.0'
            $body.configuration.settings_timezone | Should Be 'Europe/Warsaw'
            $body = New-Action1AutomationScheduleDefinition -ExistingSchedule $existingNested `
                -SettingsTimezone UTC -ApiVersion '4.0'
            $body.configuration.settings_timezone | Should Be 'UTC'
        }

        It 'distinguishes omitted targets from explicitly clearing disabled schedule targets' {
            $body = New-Action1AutomationScheduleDefinition -ExistingSchedule $existingNested `
                -Settings DISABLED -ApiVersion '4.0'
            $body.endpoints.Count | Should Be 1
            $body = New-Action1AutomationScheduleDefinition -ExistingSchedule $existingNested `
                -Settings DISABLED -Endpoints @() -ApiVersion '4.0'
            $body.endpoints.Count | Should Be 0
            ($body.endpoints -is [array]) | Should Be $true
        }

        It 'rejects null overrides and cross-version updates' {
            {
                New-Action1AutomationScheduleDefinition -ExistingSchedule $existingNested `
                    -Endpoints $null -ApiVersion '4.0'
            } | Should Throw
            {
                New-Action1AutomationScheduleDefinition -ExistingSchedule $existingFlat `
                    -Actions $null -ApiVersion '3.0'
            } | Should Throw
            {
                New-Action1AutomationScheduleDefinition -ExistingSchedule $existingFlat `
                    -ApiVersion '4.0'
            } | Should Throw
            {
                New-Action1AutomationScheduleDefinition -ExistingSchedule $existingNested `
                    -ApiVersion '3.0'
            } | Should Throw
        }

        It 'rejects incomplete identities and result pages as existing sources' {
            $existingFlat.type = 'ResultPage'
            {
                New-Action1AutomationScheduleDefinition -ExistingSchedule $existingFlat `
                    -ApiVersion '3.0'
            } | Should Throw
            $existingNested.configuration.PSObject.Properties.Remove('id')
            {
                New-Action1AutomationScheduleDefinition -ExistingSchedule $existingNested `
                    -ApiVersion '4.0'
            } | Should Throw
        }

        It 'assigns IDs to raw new v4 actions without mutating the caller' {
            $builderAction.PSObject.Properties.Remove('id')
            $body = New-Action1AutomationDefinition @builderParams -ApiVersion '4.0'
            (Test-Guid $body.configuration.actions[0].id) | Should Be $true
            $builderAction.id | Should BeNullOrEmpty
        }

        It 'reparses both request formats without losing nested arrays or quoted script text' {
            $builderAction.params | Add-Member -NotePropertyName condition_script_text `
                -NotePropertyValue 'Write-Output "a\b"'
            foreach ($version in @('3.0', '4.0')) {
                $body = New-Action1AutomationDefinition @builderParams -ApiVersion $version
                $json = ConvertTo-Json -InputObject $body `
                    -Depth $script:Action1_JsonObjectConversionDepth -Compress
                $parsed = ConvertFrom-Json -InputObject $json
                $config = $parsed
                if ($version -eq '4.0') { $config = $parsed.configuration }
                ($config.actions -is [array]) | Should Be $true
                ($config.actions[0].params.run_script_params -is [array]) | Should Be $true
                $config.actions[0].params.condition_script_text | Should Be 'Write-Output "a\b"'
            }
        }

        It 'inherits nested definitions and applies only explicit overrides' {
            $body = New-Action1AutomationDefinition -ExistingAutomation $existingNested `
                -Name Renamed -ApiVersion '4.0'
            $body.configuration.name | Should Be 'Renamed'
            $body.configuration.id | Should Be $existingNested.configuration.id
            $body.configuration.organization_id |
                Should Be $existingNested.configuration.organization_id
            $body.configuration.retry_minutes | Should Be '240'
            $body.configuration.settings | Should Be $existingNested.configuration.settings
            $body.configuration.settings_timezone | Should Be 'UTC'
            $body.configuration.start_time | Should BeNullOrEmpty
            $body.configuration.extension.values[0] | Should Be 'preserve'
            $body.endpoints.Count | Should Be 1
            $body.signatures | Should BeNullOrEmpty
            $existingNested.configuration.name | Should Be 'Existing schedule'
            $existingNested.signatures[0].object_signature.value | Should Be 'stale'
        }

        It 'preserves existing start time and IDs unless explicitly overridden' {
            $existingNested.configuration.PSObject.Properties.Remove('settings')
            $existingNested.configuration.PSObject.Properties.Remove('settings_timezone')
            $existingNested.configuration | Add-Member -NotePropertyName start_time `
                -NotePropertyValue '2026-01-01_12-00-00'
            $body = New-Action1AutomationDefinition -ExistingAutomation $existingNested `
                -ApiVersion '4.0'
            $body.configuration.start_time | Should Be '2026-01-01_12-00-00'
            $body.configuration.id | Should Be $existingNested.configuration.id
            $body = New-Action1AutomationDefinition -ExistingAutomation $existingNested `
                -ConfigurationId '33333333-3333-3333-3333-333333333333' `
                -OrganizationId '44444444-4444-4444-4444-444444444444' `
                -StartTime ([DateTimeOffset]'2026-11-25T15:00:00+01:00') `
                -RetryMinutes 120 -ApiVersion '4.0'
            $body.configuration.id | Should Be '33333333-3333-3333-3333-333333333333'
            $body.configuration.organization_id |
                Should Be '44444444-4444-4444-4444-444444444444'
            $body.configuration.start_time | Should Be '2026-11-25_14-00-00'
            $body.configuration.retry_minutes | Should Be '120'
            $existingNested.configuration.start_time | Should Be '2026-01-01_12-00-00'
        }

        It 'reuses flat instance fields while excluding known execution metadata' {
            $instance = @{
                id = 'synthetic_instance'
                type = 'AutomationInstance'
                self = 'https://example.invalid/api/3.0/automations/instances/example'
                name = 'Previous run'
                actions = @($builderAction)
                endpoints = @($builderTarget)
                retry_minutes = '120'
                start_time = '2026-01-01_12-00-00'
                status = 'Success'
                percent_completed = '100'
                endpoint_results = 'https://example.invalid/results'
                end_time = '2026-01-01_12-01-00'
                custom_option = @{ values = @('retain') }
            }
            $body = New-Action1AutomationDefinition -ExistingAutomation $instance `
                -Name Reused -ApiVersion '3.0'
            $body.id | Should Be 'synthetic_instance'
            $body.name | Should Be 'Reused'
            $body.start_time | Should Be '2026-01-01_12-00-00'
            $body.custom_option.values[0] | Should Be 'retain'
            foreach ($propertyName in @(
                'type', 'self', 'status', 'percent_completed', 'endpoint_results', 'end_time'
            )) {
                ($body.PSObject.Properties.Name -contains $propertyName) | Should Be $false
            }
            $instance.name | Should Be 'Previous run'
        }

        It 'accepts a flat API 4 instance when the caller supplies configuration identity' {
            $instance = @{
                id = '22222222-2222-2222-2222-222222222222_2026-01-01_12-00-00'
                type = 'AutomationInstance'
                name = 'Previous run'
                actions = @($builderAction)
                endpoints = @($builderTarget)
                retry_minutes = '120'
                start_time = '2026-01-01_12-00-00'
            }
            { New-Action1AutomationDefinition -ExistingAutomation $instance -ApiVersion '4.0' } |
                Should Throw
            $body = New-Action1AutomationDefinition -ExistingAutomation $instance `
                -ConfigurationId '22222222-2222-2222-2222-222222222222' `
                -OrganizationId $script:Action1_Default_Org_Id -ApiVersion '4.0'
            $body.configuration.id | Should Be '22222222-2222-2222-2222-222222222222'
            $body.configuration.start_time | Should Be '2026-01-01_12-00-00'
            $instance.id |
                Should Be '22222222-2222-2222-2222-222222222222_2026-01-01_12-00-00'
        }

        It 'requires explicit actions when an instance response contains an empty array' {
            $instance = @{
                type='AutomationInstance';name='Previous run';actions=@()
                endpoints=@($builderTarget);retry_minutes='60'
            }
            {
                New-Action1AutomationDefinition -ExistingAutomation $instance -ApiVersion '3.0'
            } | Should Throw 'The existing automation has no usable actions. Specify Actions explicitly.'
            $body = New-Action1AutomationDefinition -ExistingAutomation $instance `
                -Actions @($builderAction) -ApiVersion '3.0'
            $body.actions.Count | Should Be 1
            $instance.actions.Count | Should Be 0
        }

        It 'does not fill missing source identities or start times from creation defaults' {
            $existingNested.configuration.PSObject.Properties.Remove('id')
            {
                New-Action1AutomationDefinition -ExistingAutomation $existingNested `
                    -ApiVersion '4.0'
            } | Should Throw
            $existingNested.configuration.PSObject.Properties.Remove('organization_id')
            {
                New-Action1AutomationDefinition -ExistingAutomation $existingNested `
                    -ConfigurationId '33333333-3333-3333-3333-333333333333' -ApiVersion '4.0'
            } | Should Throw
            $body = New-Action1AutomationDefinition -ExistingAutomation $existingNested `
                -ConfigurationId '33333333-3333-3333-3333-333333333333' `
                -OrganizationId $script:Action1_Default_Org_Id -ApiVersion '4.0'
            $body.configuration.start_time | Should BeNullOrEmpty
        }

        It 'does not generate missing action IDs for an existing definition' {
            $builderAction.PSObject.Properties.Remove('id')
            $body = New-Action1AutomationDefinition -ExistingAutomation $existingNested `
                -ApiVersion '4.0'
            ($body.configuration.actions[0].PSObject.Properties.Name -contains 'id') |
                Should Be $false
        }

        It 'preserves existing disabled schedules without requiring targets' {
            $existingNested.configuration.settings = 'DISABLED'
            $existingNested.endpoints = @()
            $body = New-Action1AutomationDefinition -ExistingAutomation $existingNested `
                -ApiVersion '4.0'
            $body.endpoints.Count | Should Be 0
            $body.configuration.id | Should Be $existingNested.configuration.id
        }

        It 'accepts ExistingAutomation as the schedule source and allows explicit ID overrides' {
            $body = New-Action1AutomationScheduleDefinition -ExistingAutomation $existingNested `
                -ConfigurationId '33333333-3333-3333-3333-333333333333' `
                -OrganizationId '44444444-4444-4444-4444-444444444444' -ApiVersion '4.0'
            $body.configuration.id | Should Be '33333333-3333-3333-3333-333333333333'
            $body.configuration.organization_id |
                Should Be '44444444-4444-4444-4444-444444444444'
            $existingNested.configuration.id | Should Be '22222222-2222-2222-2222-222222222222'
        }

        It 'builds a schedule from an instance using explicit missing schedule properties' {
            $instance = @{
                type='AutomationInstance';name='Previous run';actions=@($builderAction)
                endpoints=@($builderTarget);retry_minutes='60'
            }
            $body = New-Action1AutomationScheduleDefinition -ExistingAutomation $instance `
                -Settings DISABLED -SettingsTimezone UTC -ApiVersion '3.0'
            $body.settings | Should Be 'DISABLED'
            $body.settings_timezone | Should Be 'UTC'
            $body.name | Should Be 'Previous run'
        }

        It 'accepts explicit overrides for missing source fields without mutating the source' {
            $source = @{ extension = @{ values = @('retain') } }
            $body = New-Action1AutomationDefinition -ExistingAutomation $source `
                @builderParams -ApiVersion '3.0'
            $body.name | Should Be 'Synthetic automation'
            $body.extension.values[0] | Should Be 'retain'
            $source.ContainsKey('name') | Should Be $false
            { New-Action1AutomationDefinition -ExistingAutomation $source -ApiVersion '3.0' } |
                Should Throw 'The existing automation has no endpoints. Specify Endpoints explicitly.'
        }

        It 'rejects null, JSON text, and result pages as existing automation inputs' {
            {
                New-Action1AutomationDefinition -ExistingAutomation $null -ApiVersion '3.0'
            } | Should Throw
            {
                New-Action1AutomationDefinition -ExistingAutomation '{}' -ApiVersion '3.0'
            } | Should Throw
            {
                New-Action1AutomationDefinition -ExistingAutomation @{ items=@($existingFlat) } `
                    -ApiVersion '3.0'
            } | Should Throw
        }

        It 'never calls the request helper while constructing objects' {
            $null = New-Action1AutomationDefinition @builderParams -ApiVersion '4.0'
            $null = New-Action1AutomationScheduleDefinition -ExistingSchedule $existingFlat `
                -ApiVersion '3.0'
            $null = New-Action1AutomationDefinition -ExistingAutomation $existingNested `
                -ApiVersion '4.0'
            Assert-MockCalled Invoke-Action1ApiRequest -Times 0 -Exactly -Scope It
            Assert-MockCalled Invoke-WebRequest -Times 0 -Exactly -Scope It
        }
    }

    Describe 'Automation builders through the existing request boundary' {
        BeforeEach {
            $script:Action1_BaseURI = 'https://example.invalid/api/4.0'
            $script:Action1_Default_Org_Id = '11111111-1111-1111-1111-111111111111'
            $script:Action1_DebugEnabled = $false
            $script:Action1_Token = @{ access_token = 'synthetic-token' }
            $script:capturedAutomationRequest = $null
            Mock Initialize-Action1DefaultOrg { $true }
            Mock Initialize-Action1Token { $true }
            Mock Invoke-WebRequest {
                $script:capturedAutomationRequest = @{
                    Method = $Method
                    Uri    = $Uri
                    Body   = ConvertFrom-Json -InputObject $Body
                }
                [pscustomobject]@{ StatusCode = 200; Content = '{"id":"synthetic-result"}' }
            }
        }

        It 'serializes both versions unchanged for run-now POST and schedule POST/PATCH' {
            foreach ($version in @('3.0', '4.0')) {
                $script:Action1_BaseURI = "https://example.invalid/api/$version"
                $action = New-Action1AutomationAction -Name Test -TemplateId run_script `
                    -Parameters @{ run_script_id = 'synthetic_script' }
                $target = New-Action1AutomationTarget -Id synthetic_group -Type EndpointGroup
                $common = @{Name='Test';Actions=@($action);Endpoints=@($target);RetryMinutes=60}
                $body = New-Action1AutomationDefinition @common
                (Start-Action1Automation -AutomationDefinition $body -Force).id |
                    Should Be 'synthetic-result'
                $capturedAutomationRequest.Method | Should Be 'POST'
                $capturedAutomationRequest.Uri | Should Match '/automations/instances/'
                $scheduleBody = New-Action1AutomationScheduleDefinition @common `
                    -Settings DISABLED
                $null = New-Action1AutomationSchedule `
                    -AutomationScheduleDefinition $scheduleBody -Force
                $capturedAutomationRequest.Method | Should Be 'POST'
                $capturedAutomationRequest.Uri | Should Match '/automations/schedules/'
                $null = Update-Action1AutomationSchedule -AutomationInstanceId synthetic_schedule `
                    -AutomationScheduleDefinition $scheduleBody -Force
                $capturedAutomationRequest.Method | Should Be 'PATCH'
                $capturedAutomationRequest.Uri | Should Match '/synthetic_schedule$'
                if ($version -eq '4.0') {
                    $capturedAutomationRequest.Body.configuration.settings | Should Be 'DISABLED'
                }
                else {
                    $capturedAutomationRequest.Body.settings | Should Be 'DISABLED'
                }
            }
            Assert-MockCalled Invoke-WebRequest -Times 6 -Exactly -Scope It
        }

        It 'still honors WhatIf with Force for all three submission commands' {
            $body = @{ configuration = @{ name = 'Test' }; endpoints = @() }
            $null = Start-Action1Automation -AutomationDefinition $body -Force -WhatIf
            $null = New-Action1AutomationSchedule -AutomationScheduleDefinition $body `
                -Force -WhatIf
            $null = Update-Action1AutomationSchedule -AutomationInstanceId synthetic_schedule `
                -AutomationScheduleDefinition $body -Force -WhatIf
            Assert-MockCalled Invoke-WebRequest -Times 0 -Exactly -Scope It
        }
    }
}
