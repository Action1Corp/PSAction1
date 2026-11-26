# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

# Windows PowerShell 5.1 / Pester 3.4 or later. No real keys or network calls.
$modulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'PSAction1.psd1'
Import-Module $modulePath -Force -ErrorAction Stop

InModuleScope PSAction1 {
    Describe 'Automation submission signing' {
        $script:submissionSignatureValidator = (Get-Command Test-Action1Signature).ScriptBlock
        $script:submissionSignatureAdder = (Get-Command Add-Action1Signature).ScriptBlock
        $script:submissionVersionResolver = (Get-Command Resolve-Action1AutomationApiVersion).ScriptBlock
        $submissionCases = @(
            @{
                CommandName = 'New-Action1AutomationSchedule'
                Method = 'POST'
                Route = '/automations/schedules/22222222-2222-2222-2222-222222222222'
            }
            @{
                CommandName = 'Update-Action1AutomationSchedule'
                Method = 'PATCH'
                Route = '/automations/schedules/22222222-2222-2222-2222-222222222222/synthetic_schedule'
            }
            @{
                CommandName = 'Start-Action1Automation'
                Method = 'POST'
                Route = '/automations/instances/22222222-2222-2222-2222-222222222222'
            }
        )

        BeforeEach {
            $script:savedSubmissionBaseUri = $script:Action1_BaseURI
            $script:savedSubmissionOrgId = $script:Action1_Default_Org_Id
            $script:Action1_BaseURI = 'https://example.invalid/api/4.0'
            $script:Action1_Default_Org_Id = '22222222-2222-2222-2222-222222222222'
            $script:submissionBody = [pscustomobject]@{
                configuration = [pscustomobject]@{
                    type = 'AutomationScheduleConfiguration'
                    organization_id = '22222222-2222-2222-2222-222222222222'
                    name = 'Synthetic automation'
                    actions = @(@{ id = 'synthetic-action' })
                }
                endpoints = @(@{ id = 'ALL'; type = 'EndpointGroup' })
                signatures = @(@{ stale = $true })
            }
            $script:submissionResponse = [pscustomobject]@{ id = 'synthetic-result' }
            $script:capturedSubmission = $null
            $script:submitAutomation = {
                param($commandName, $definition, $options = @{})

                $submissionParams = @{ Force = $true }
                if ($commandName -eq 'Start-Action1Automation') {
                    $submissionParams.AutomationDefinition = $definition
                }
                else {
                    $submissionParams.AutomationScheduleDefinition = $definition
                }
                if ($commandName -eq 'Update-Action1AutomationSchedule') {
                    $submissionParams.AutomationInstanceId = 'synthetic_schedule'
                }
                & $commandName @submissionParams @options
            }
            Mock Initialize-Action1DefaultOrg { $true }
            # Pester 3 keeps mock implementations between cases; reset every override.
            Mock Resolve-Action1AutomationApiVersion { & $script:submissionVersionResolver }
            Mock Add-Action1Signature {
                & $script:submissionSignatureAdder -InputObject $InputObject
            }
            Mock Test-Action1Signature {
                & $script:submissionSignatureValidator -InputObject $InputObject
            }
            Mock New-Action1Signature {
                [pscustomobject]@{
                    alg = 'EdDSA'
                    iat = 1795614034
                    kid = 'synthetic-key'
                    value = 'synthetic-signature'
                }
            }
            Mock Invoke-Action1ApiRequest {
                $script:capturedSubmission = @{
                    Method = $Method
                    Path = $Path
                    Body = $Body
                }
                $script:submissionResponse
            }
            Mock Invoke-WebRequest { throw 'Tests must not call the network.' }
        }

        AfterEach {
            $script:Action1_BaseURI = $savedSubmissionBaseUri
            $script:Action1_Default_Org_Id = $savedSubmissionOrgId
        }

        It '<CommandName> signs API 4 definitions before sending the expected request' `
            -TestCases $submissionCases {
            param($CommandName, $Method, $Route)

            $output = @(& $submitAutomation $CommandName $submissionBody)
            $output.Count | Should Be 1
            [object]::ReferenceEquals($output[0], $submissionResponse) | Should Be $true
            $capturedSubmission.Method | Should Be $Method
            $capturedSubmission.Path | Should Be ($script:Action1_BaseURI + $Route)
            Test-Action1Signature -InputObject $capturedSubmission.Body | Should Be $true
            $capturedSubmission.Body.signatures.Count | Should Be 1
            $capturedSubmission.Body.signatures[0].object_signature.value |
                Should Be 'synthetic-signature'
            $capturedSubmission.Body.signatures[0].object_reference.id |
                Should Be $capturedSubmission.Body.configuration.id
            Assert-MockCalled New-Action1Signature -Times 1 -Exactly -Scope It
            Assert-MockCalled Invoke-Action1ApiRequest -Times 1 -Exactly -Scope It
        }

        It '<CommandName> passes API 3 definitions unchanged without signing or signature checks' `
            -TestCases $submissionCases {
            param($CommandName)

            $script:Action1_BaseURI = 'https://example.invalid/api/3.0/'
            $body = @{ name = 'Synthetic automation'; actions = @(); endpoints = @() }
            Mock Test-Action1Signature { throw 'API 3 must not validate signatures.' }
            $null = & $submitAutomation $CommandName $body
            [object]::ReferenceEquals($capturedSubmission.Body, $body) | Should Be $true
            Assert-MockCalled New-Action1Signature -Times 0 -Exactly -Scope It
            Assert-MockCalled Test-Action1Signature -Times 0 -Exactly -Scope It
            Assert-MockCalled Invoke-Action1ApiRequest -Times 1 -Exactly -Scope It
        }

        It '<CommandName> blocks the request when signature fields are incomplete' `
            -TestCases $submissionCases {
            param($CommandName)

            Mock New-Action1Signature { [pscustomobject]@{ value = 'incomplete' } }
            $script:submissionErrors = @()
            $output = @(& $submitAutomation $CommandName $submissionBody @{
                ErrorAction = 'SilentlyContinue'; ErrorVariable = 'script:submissionErrors'
            })
            $output.Count | Should Be 0
            $submissionErrors.Count | Should Be 1
            $submissionErrors[0].Exception.Message | Should Match 'invalid or missing signatures'
            Assert-MockCalled Invoke-Action1ApiRequest -Times 0 -Exactly -Scope It
        }

        It '<CommandName> gates the request on the signature validator result' `
            -TestCases $submissionCases {
            param($CommandName)

            $commandToSubmit = $CommandName
            Mock Test-Action1Signature { $false }
            { & $submitAutomation $commandToSubmit $submissionBody @{ ErrorAction = 'Stop' } } |
                Should Throw
            Assert-MockCalled Test-Action1Signature -Times 1 -Exactly -Scope It `
                -ParameterFilter {
                    $InputObject.signatures[0].object_signature.value -eq 'synthetic-signature'
                }
            Assert-MockCalled Invoke-Action1ApiRequest -Times 0 -Exactly -Scope It
        }

        It '<CommandName> stops when signing throws' -TestCases $submissionCases {
            param($CommandName)

            $commandToSubmit = $CommandName
            Mock New-Action1Signature { throw 'Synthetic signing failure.' }
            { & $submitAutomation $commandToSubmit $submissionBody } |
                Should Throw 'Synthetic signing failure.'
            Assert-MockCalled Invoke-Action1ApiRequest -Times 0 -Exactly -Scope It
        }

        It '<CommandName> stops when the signing helper reports a nonterminating error' `
            -TestCases $submissionCases {
            param($CommandName)

            $commandToSubmit = $CommandName
            Mock Add-Action1Signature { Write-Error 'Synthetic signing failure.' }
            { & $submitAutomation $commandToSubmit $submissionBody } |
                Should Throw 'Synthetic signing failure.'
            Assert-MockCalled Invoke-Action1ApiRequest -Times 0 -Exactly -Scope It
        }

        It '<CommandName> blocks the request if signing returns nothing' `
            -TestCases $submissionCases {
            param($CommandName)

            $commandToSubmit = $CommandName
            Mock Add-Action1Signature { $null }
            { & $submitAutomation $commandToSubmit $submissionBody @{ ErrorAction = 'Stop' } } |
                Should Throw 'invalid or missing signatures'
            Assert-MockCalled Invoke-Action1ApiRequest -Times 0 -Exactly -Scope It
        }

        It '<CommandName> skips version resolution, signing, and requests for WhatIf with Force' `
            -TestCases $submissionCases {
            param($CommandName)

            Mock Resolve-Action1AutomationApiVersion { throw 'WhatIf must skip resolution.' }
            Mock Test-Action1Signature { throw 'WhatIf must skip validation.' }
            $before = ConvertTo-Json $submissionBody -Depth 10 -Compress
            $output = @(& $submitAutomation $CommandName $submissionBody @{ WhatIf = $true })
            $output.Count | Should Be 0
            ConvertTo-Json $submissionBody -Depth 10 -Compress | Should Be $before
            Assert-MockCalled Resolve-Action1AutomationApiVersion -Times 0 -Exactly -Scope It
            Assert-MockCalled New-Action1Signature -Times 0 -Exactly -Scope It
            Assert-MockCalled Test-Action1Signature -Times 0 -Exactly -Scope It
            Assert-MockCalled Invoke-Action1ApiRequest -Times 0 -Exactly -Scope It
        }

        It '<CommandName> blocks requests when the API version cannot be resolved' `
            -TestCases $submissionCases {
            param($CommandName)

            $commandToSubmit = $CommandName
            $script:Action1_BaseURI = 'https://example.invalid'
            { & $submitAutomation $commandToSubmit $submissionBody } | Should Throw
            Assert-MockCalled New-Action1Signature -Times 0 -Exactly -Scope It
            Assert-MockCalled Invoke-Action1ApiRequest -Times 0 -Exactly -Scope It
        }

        It '<CommandName> preserves null-response error handling' -TestCases $submissionCases {
            param($CommandName)

            $commandToSubmit = $CommandName
            Mock Invoke-Action1ApiRequest { $null }
            { & $submitAutomation $commandToSubmit $submissionBody @{ ErrorAction = 'Stop' } } |
                Should Throw 'Failed to'
            Assert-MockCalled Invoke-Action1ApiRequest -Times 1 -Exactly -Scope It
        }
    }
}
