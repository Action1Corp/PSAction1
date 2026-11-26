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
    Describe 'Add-Action1Signature' {
        BeforeEach {
            $script:signatureConfig = [ordered]@{
                id = '11111111-1111-1111-1111-111111111111'
                type = 'AutomationScheduleConfiguration'
                organization_id = '22222222-2222-2222-2222-222222222222'
                name = 'Synthetic automation'
                actions = @(@{ id = 'synthetic-action'; params = @{ value = 42 } })
            }
            $script:signatureBody = [pscustomobject]@{
                configuration = [pscustomobject]$signatureConfig
                endpoints = @(@{ id = 'synthetic-endpoint'; type = 'Endpoint' })
                extension = @{ values = @('preserve') }
            }
            $script:syntheticSignature = [pscustomobject]@{
                alg = 'EdDSA'
                iat = 1795614034
                kid = 'synthetic-key'
                value = 'synthetic-signature'
            }
            $script:capturedSignatureConfig = $null
            Mock New-Action1Signature {
                $script:capturedSignatureConfig = $ObjectConfig
                $script:syntheticSignature
            }
            Mock Invoke-WebRequest { throw 'Tests must not call the network.' }
            Mock Invoke-Action1ApiRequest { throw 'Tests must not call the API.' }
        }

        It 'signs only the configuration and attaches one root signature with the same identity' {
            $result = @(Add-Action1Signature -InputObject $signatureBody)
            $result.Count | Should Be 1
            [object]::ReferenceEquals($result[0], $signatureBody) | Should Be $true
            $body = $result[0]
            $body.configuration.id | Should Be '11111111-1111-1111-1111-111111111111'
            [object]::ReferenceEquals($capturedSignatureConfig, $body.configuration) |
                Should Be $true
            $capturedSignatureConfig.PSObject.Properties.Name -contains 'endpoints' |
                Should Be $false
            $capturedSignatureConfig.PSObject.Properties.Name -contains 'signatures' |
                Should Be $false
            ($body.signatures -is [array]) | Should Be $true
            $body.signatures.Count | Should Be 1
            $reference = $body.signatures[0].object_reference
            $reference.id | Should Be $body.configuration.id
            $reference.type | Should Be $body.configuration.type
            $reference.organization_id | Should Be $body.configuration.organization_id
            [object]::ReferenceEquals($body.signatures[0].object_signature, $syntheticSignature) |
                Should Be $true
            Assert-MockCalled New-Action1Signature -Times 1 -Exactly -Scope It
            Assert-MockCalled Invoke-WebRequest -Times 0 -Exactly -Scope It
            Assert-MockCalled Invoke-Action1ApiRequest -Times 0 -Exactly -Scope It
        }

        It 'preserves endpoints, extensions, and nested configuration values' {
            $endpoints = $signatureBody.endpoints
            $extension = $signatureBody.extension
            $actions = $signatureBody.configuration.actions
            $body = Add-Action1Signature -InputObject $signatureBody
            [object]::ReferenceEquals($body.endpoints, $endpoints) | Should Be $true
            [object]::ReferenceEquals($body.extension, $extension) | Should Be $true
            [object]::ReferenceEquals($body.configuration.actions, $actions) | Should Be $true
        }

        It 'supports hashtable and ordered dictionary bodies and configurations' {
            foreach ($body in @(@{ configuration = @{} }, [ordered]@{ configuration = @{} })) {
                $body.configuration = $signatureConfig
                $result = Add-Action1Signature -InputObject $body
                [object]::ReferenceEquals($result, $body) | Should Be $true
                $result.Contains('signatures') | Should Be $true
                ($result.signatures -is [array]) | Should Be $true
                $result.signatures[0].object_reference.id | Should Be $result.configuration.id
            }
        }

        It 'generates a GUID before signing when id is absent, null, empty, or whitespace' {
            $ids = @()
            foreach ($idState in @('absent', $null, '', ' ')) {
                $config = [ordered]@{
                    type = 'SyntheticConfiguration'
                    organization_id = $signatureConfig.organization_id
                }
                if ($idState -ne 'absent') { $config['id'] = $idState }
                $body = Add-Action1Signature -InputObject @{ configuration = $config }
                Test-Guid -Guid $body.configuration.id | Should Be $true
                $body.signatures[0].object_reference.id | Should Be $body.configuration.id
                $capturedSignatureConfig.id | Should Be $body.configuration.id
                $ids += $body.configuration.id
            }
            @($ids | Select-Object -Unique).Count | Should Be 4
        }

        It 'keeps the configuration id when signing the same body again' {
            $signatureBody.configuration.PSObject.Properties.Remove('id')
            $body = Add-Action1Signature -InputObject $signatureBody
            $firstId = $body.configuration.id
            $body = Add-Action1Signature -InputObject $body
            $body.configuration.id | Should Be $firstId
            $body.signatures.Count | Should Be 1
        }

        It 'replaces prior signatures rather than retaining stale entries' {
            $signatureBody | Add-Member -NotePropertyName signatures `
                -NotePropertyValue @(@{ stale = $true }, @{ stale = $true })
            $body = Add-Action1Signature -InputObject $signatureBody
            $body.signatures.Count | Should Be 1
            $body.signatures[0].object_signature.value | Should Be synthetic-signature
        }

        It 'supports another configuration property and object type' {
            $signatureConfig['type'] = 'SyntheticPolicyConfiguration'
            $body = Add-Action1Signature -InputObject @{ policy = $signatureConfig } `
                -ConfigurationProperty policy
            $body.signatures[0].object_reference.type | Should Be SyntheticPolicyConfiguration
            $body.policy.id | Should Be $signatureConfig.id
        }

        It 'signs a root object without including its existing signatures in signed data' {
            foreach ($config in @($signatureConfig, [pscustomobject]$signatureConfig)) {
                if ($config -is [Collections.IDictionary]) {
                    $config['signatures'] = @(@{ stale = $true })
                }
                else {
                    $config | Add-Member -NotePropertyName signatures `
                        -NotePropertyValue @(@{ stale = $true }) -Force
                }
                $body = Add-Action1Signature -InputObject $config -ConfigurationProperty ''
                [object]::ReferenceEquals($config, $body) | Should Be $true
                $capturedSignatureConfig.PSObject.Properties.Name -contains 'signatures' |
                    Should Be $false
                $body.signatures[0].object_reference.id | Should Be $body.id
            }
        }

        It 'forwards explicit key and SecureString credentials to the signer' {
            $securePassphrase = New-Object Security.SecureString
            $securePassphrase.AppendChar('x')
            $securePassphrase.MakeReadOnly()
            $null = Add-Action1Signature -InputObject $signatureBody `
                -Action1KeyPath 'synthetic.key' -Passphrase $securePassphrase
            Assert-MockCalled New-Action1Signature -Times 1 -Exactly -Scope It `
                -ParameterFilter {
                    $Action1KeyPath -eq 'synthetic.key' -and
                    [object]::ReferenceEquals($Passphrase, $securePassphrase)
                }
        }

        It 'leaves the entire input unchanged and returns nothing if signing fails' {
            $signatureBody.configuration.PSObject.Properties.Remove('id')
            $signatureBody | Add-Member -NotePropertyName signatures `
                -NotePropertyValue @(@{ old = $true })
            $before = ConvertTo-Json $signatureBody -Depth 100 -Compress
            Mock New-Action1Signature { throw 'Synthetic signing failure.' }
            $output = @()
            $failure = $null
            try { $output = @(Add-Action1Signature -InputObject $signatureBody) }
            catch { $failure = $_ }
            $failure.Exception.Message | Should Be 'Synthetic signing failure.'
            $output.Count | Should Be 0
            ConvertTo-Json $signatureBody -Depth 100 -Compress | Should Be $before
        }

        It 'rejects malformed ids instead of replacing them' {
            foreach ($invalidId in @('malformed', 123, @{}, @('value'))) {
                $signatureBody.configuration.id = $invalidId
                { Add-Action1Signature -InputObject $signatureBody } | Should Throw
            }
            Assert-MockCalled New-Action1Signature -Times 0 -Exactly -Scope It
        }

        It 'rejects missing or invalid type and organization identity' {
            foreach ($invalid in @($null, '', ' ', 42, @{})) {
                $signatureBody.configuration.type = $invalid
                { Add-Action1Signature -InputObject $signatureBody } | Should Throw
            }
            $signatureBody.configuration.type = 'SyntheticConfiguration'
            foreach ($invalid in @($null, '', ' ', 'malformed', 42, @{})) {
                $signatureBody.configuration.organization_id = $invalid
                { Add-Action1Signature -InputObject $signatureBody } | Should Throw
            }
            Assert-MockCalled New-Action1Signature -Times 0 -Exactly -Scope It
        }

        It 'rejects null, scalar, array, empty, and missing configuration inputs' {
            foreach ($invalid in @($null, '{}', 42, @('value'), @{}, [pscustomobject]@{},
                @{ configuration = $null }, @{ configuration = 'invalid' },
                @{ configuration = @{} }, @{ configuration = @(@{}) })) {
                { Add-Action1Signature -InputObject $invalid } | Should Throw
            }
            Assert-MockCalled New-Action1Signature -Times 0 -Exactly -Scope It
        }

        It 'rejects null, whitespace, and signatures as the configuration property' {
            foreach ($invalid in @($null, ' ', 'signatures')) {
                {
                    Add-Action1Signature -InputObject $signatureBody `
                        -ConfigurationProperty $invalid
                } | Should Throw
            }
            Assert-MockCalled New-Action1Signature -Times 0 -Exactly -Scope It
        }

        It 'supports API 4 run-now and schedule builders without exporting the helper' {
            $action = New-Action1AutomationAction -Name 'Synthetic action' `
                -TemplateId custom -Parameters @{ value = 42 }
            $target = New-Action1AutomationTarget -Id ALL -Type EndpointGroup
            $builderParams = @{
                Name = 'Synthetic automation'
                Actions = @($action)
                Endpoints = @($target)
                RetryMinutes = 10
                ApiVersion = '4.0'
                OrganizationId = $signatureConfig.organization_id
            }
            $runNow = New-Action1AutomationDefinition @builderParams
            $schedule = New-Action1AutomationScheduleDefinition @builderParams `
                -Settings 'DISABLED' -SettingsTimezone UTC
            foreach ($definition in @($runNow, $schedule)) {
                $body = Add-Action1Signature -InputObject $definition
                $body.signatures[0].object_reference.id | Should Be $body.configuration.id
            }
            (Get-Module PSAction1).ExportedFunctions.Keys -contains 'Add-Action1Signature' |
                Should Be $false
        }
    }
}
