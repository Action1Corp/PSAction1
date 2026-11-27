# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

# Windows PowerShell 5.1 / Pester 3.4 or later. No network calls.
$modulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'PSAction1.psd1'
Import-Module $modulePath -Force -ErrorAction Stop

Describe 'Get-Action1AutomationDeploymentStatuses export' {
    It 'exports the command from the module manifest' {
        $command = Get-Command Get-Action1AutomationDeploymentStatuses -Module PSAction1
        $command.Name | Should Be 'Get-Action1AutomationDeploymentStatuses'
    }
}

InModuleScope PSAction1 {
    Describe 'Get-Action1AutomationDeploymentStatuses' {
        BeforeEach {
            $script:savedDeploymentBaseUri = $script:Action1_BaseURI
            $script:Action1_BaseURI = 'https://example.invalid/api/4.0'
            $script:deploymentResponse = [pscustomobject]@{
                synthetic = 'deployment status response'
            }
            # ResultPage metadata matches the API shape; from is intentionally absent.
            $script:deploymentPage = [pscustomobject]@{
                id = '1'
                type = 'ResultPage'
                self = 'https://example.invalid/api/4.0/automations/schedules/synthetic'
                items = @($script:deploymentResponse)
                total_items = '1'
                limit = '200'
                next_page = ''
                prev_page = ''
            }
            Mock Initialize-Action1DefaultOrg { $true }
            Mock Get-Action1DefaultOrgId { '22222222-2222-2222-2222-222222222222' }
            Mock Invoke-Action1ApiRequest { $script:deploymentPage }
            Mock Invoke-WebRequest { throw 'Tests must not call the network.' }
        }

        AfterEach {
            $script:Action1_BaseURI = $savedDeploymentBaseUri
        }

        It 'requests the deployment statuses route with default organization and page size' {
            $output = Get-Action1AutomationDeploymentStatuses -AutomationInstanceId 'synthetic_schedule'
            [object]::ReferenceEquals($output, $deploymentResponse) | Should Be $true
            Assert-MockCalled Initialize-Action1DefaultOrg -Times 1 -Exactly -Scope It
            Assert-MockCalled Get-Action1DefaultOrgId -Times 1 -Exactly -Scope It
            Assert-MockCalled Invoke-Action1ApiRequest -Times 1 -Exactly -Scope It `
                -ParameterFilter {
                    $Method -eq 'GET' -and
                    $Path -eq ('https://example.invalid/api/4.0/automations/schedules/' +
                        '22222222-2222-2222-2222-222222222222/synthetic_schedule/deployment-statuses') -and
                    $Label -eq "Automation schedule 'synthetic_schedule' deployment statuses" -and
                    $null -eq $Body -and $AddArgs -eq 'from=0&limit=200'
                }
            Assert-MockCalled Invoke-WebRequest -Times 0 -Exactly -Scope It
        }

        It 'accepts the schedule ID positionally' {
            $output = Get-Action1AutomationDeploymentStatuses 'synthetic_schedule'
            [object]::ReferenceEquals($output, $deploymentResponse) | Should Be $true
        }

        It 'streams items from every page when from is absent and totals are strings' {
            $firstItem = [pscustomobject]@{ synthetic = 'first' }
            $secondItem = [pscustomobject]@{ synthetic = 'second' }
            $script:deploymentPage.items = @($firstItem)
            $script:deploymentPage.total_items = '2'
            $script:deploymentPage.limit = '1'
            $script:deploymentSecondPage = [pscustomobject]@{
                items = @($secondItem); total_items = '2'; limit = '1'; next_page = ''
            }
            Mock Invoke-Action1ApiRequest {
                if ($AddArgs -eq 'from=0&limit=1') { return $script:deploymentPage }
                if ($AddArgs -eq 'from=1&limit=1') { return $script:deploymentSecondPage }
                throw "Unexpected page query: $AddArgs"
            }
            $output = @(Get-Action1AutomationDeploymentStatuses 'synthetic_schedule' -Limit 1)
            $output.Count | Should Be 2
            [object]::ReferenceEquals($output[0], $firstItem) | Should Be $true
            [object]::ReferenceEquals($output[1], $secondItem) | Should Be $true
            Assert-MockCalled Invoke-Action1ApiRequest -Times 2 -Exactly -Scope It
        }

        It 'emits page envelopes with AsPages and honors a custom page size' {
            $script:deploymentPage.limit = '50'
            $output = @(Get-Action1AutomationDeploymentStatuses 'synthetic_schedule' -AsPages -Limit 50)
            $output.Count | Should Be 1
            $output[0].PageNumber | Should Be 1
            $output[0].Items.Count | Should Be 1
            [object]::ReferenceEquals($output[0].Items[0], $deploymentResponse) | Should Be $true
            $output[0].TotalItems | Should Be '1'
            $output[0].Limit | Should Be '50'
            $output[0].NextPage | Should Be ''
            Assert-MockCalled Invoke-Action1ApiRequest -Times 1 -Exactly -Scope It `
                -ParameterFilter { $AddArgs -eq 'from=0&limit=50' }
        }

        It 'supports AsPage as an alias' {
            $output = Get-Action1AutomationDeploymentStatuses 'synthetic_schedule' -AsPage
            $output.PageNumber | Should Be 1
            $output.Items.Count | Should Be 1
        }

        It 'returns no items for an empty ResultPage with string metadata' {
            $script:deploymentPage.items = @()
            $script:deploymentPage.total_items = '0'
            $script:deploymentPage.limit = '50'
            $output = @(Get-Action1AutomationDeploymentStatuses 'synthetic_schedule' -Limit 50)
            $output.Count | Should Be 0
            Assert-MockCalled Invoke-Action1ApiRequest -Times 1 -Exactly -Scope It
        }

        It 'preserves an empty ResultPage as an envelope when AsPages is set' {
            $script:deploymentPage.items = @()
            $script:deploymentPage.total_items = '0'
            $script:deploymentPage.limit = '50'
            $output = @(Get-Action1AutomationDeploymentStatuses 'synthetic_schedule' -AsPages -Limit 50)
            $output.Count | Should Be 1
            $output[0].Items.Count | Should Be 0
            $output[0].TotalItems | Should Be '0'
            $output[0].Limit | Should Be '50'
            Assert-MockCalled Invoke-Action1ApiRequest -Times 1 -Exactly -Scope It
        }

        It 'rejects page sizes outside the supported range before requesting data' {
            { Get-Action1AutomationDeploymentStatuses 'synthetic_schedule' -Limit 0 } |
                Should Throw
            { Get-Action1AutomationDeploymentStatuses 'synthetic_schedule' -Limit 201 } |
                Should Throw
            Assert-MockCalled Invoke-Action1ApiRequest -Times 0 -Exactly -Scope It
        }

        It 'returns no response when the request helper returns null' {
            Mock Invoke-Action1ApiRequest { $null }
            $output = Get-Action1AutomationDeploymentStatuses 'synthetic_schedule'
            ($null -eq $output) | Should Be $true
        }

        It 'propagates terminating request errors' {
            Mock Invoke-Action1ApiRequest { throw 'Synthetic request failure.' }
            { Get-Action1AutomationDeploymentStatuses 'synthetic_schedule' } |
                Should Throw 'Synthetic request failure.'
        }

        It 'does not send a request when organization initialization fails' {
            Mock Initialize-Action1DefaultOrg { throw 'Synthetic missing organization.' }
            { Get-Action1AutomationDeploymentStatuses 'synthetic_schedule' } |
                Should Throw 'Synthetic missing organization.'
            Assert-MockCalled Invoke-Action1ApiRequest -Times 0 -Exactly -Scope It
        }

        It 'rejects null and empty IDs before requesting data' {
            { Get-Action1AutomationDeploymentStatuses -AutomationInstanceId $null } |
                Should Throw
            { Get-Action1AutomationDeploymentStatuses -AutomationInstanceId '' } |
                Should Throw
            Assert-MockCalled Invoke-Action1ApiRequest -Times 0 -Exactly -Scope It
        }

        It 'declares a mandatory positional string without pipeline input' {
            $command = Get-Command Get-Action1AutomationDeploymentStatuses
            $parameter = $command.Parameters['AutomationInstanceId']
            $parameter.ParameterType | Should Be ([string])
            $binding = @($parameter.Attributes | Where-Object {
                $_ -is [System.Management.Automation.ParameterAttribute]
            })[0]
            $binding.Mandatory | Should Be $true
            $binding.Position | Should Be 0
            $binding.ValueFromPipeline | Should Be $false
            $binding.ValueFromPipelineByPropertyName | Should Be $false
        }
    }
}
