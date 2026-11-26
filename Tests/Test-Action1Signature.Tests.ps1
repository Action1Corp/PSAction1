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
    Describe 'Test-Action1Signature' {
        BeforeEach {
            $script:signatureEntry = @{
                object_reference = @{
                    type = 'AutomationScheduleConfiguration'
                    id = '11111111-1111-1111-1111-111111111111'
                    organization_id = '22222222-2222-2222-2222-222222222222'
                }
                object_signature = @{
                    alg = 'EdDSA'
                    iat = 1795614034
                    kid = 'synthetic-key'
                    value = 'synthetic-signature'
                }
            }
            $script:signatureRequest = @{ signatures = @($signatureEntry) }
        }

        It 'returns one Boolean for dictionary, ordered dictionary, and JSON objects' {
            $json = ConvertTo-Json $signatureRequest -Depth 10
            foreach ($body in @($signatureRequest,
                [ordered]@{ signatures = @($signatureEntry) },
                (ConvertFrom-Json $json))) {
                $output = @(Test-Action1Signature -InputObject $body)
                $output.Count | Should Be 1
                ($output[0] -is [bool]) | Should Be $true
                $output[0] | Should Be $true
            }
        }

        It 'does not alter the supplied request' {
            $before = ConvertTo-Json $signatureRequest -Depth 10 -Compress
            $null = Test-Action1Signature -InputObject $signatureRequest
            ConvertTo-Json $signatureRequest -Depth 10 -Compress | Should Be $before
        }

        It 'rejects null through parameter validation' {
            { Test-Action1Signature -InputObject $null } | Should Throw
        }

        It 'returns false for unsupported requests or missing signatures' {
            foreach ($invalid in @('', '{}', 42, @('value'), @{}, [pscustomobject]@{})) {
                Test-Action1Signature -InputObject $invalid | Should Be $false
            }
        }

        It 'requires a nonempty array rather than a scalar signature entry' {
            foreach ($invalid in @($null, '', @(), @{}, $signatureEntry, 42)) {
                $signatureRequest.signatures = $invalid
                Test-Action1Signature -InputObject $signatureRequest | Should Be $false
            }
        }

        It 'rejects malformed entries, references, and signature objects' {
            foreach ($invalid in @($null, '', 42, @(), @{}, [pscustomobject]@{})) {
                Test-Action1Signature -InputObject @{ signatures = @($invalid) } |
                    Should Be $false
                Test-Action1Signature -InputObject @{
                    signatures = @(@{
                        object_reference = $invalid
                        object_signature = $signatureEntry.object_signature
                    })
                } | Should Be $false
                Test-Action1Signature -InputObject @{
                    signatures = @(@{
                        object_reference = $signatureEntry.object_reference
                        object_signature = $invalid
                    })
                } | Should Be $false
            }
        }

        It 'requires a nonempty string reference type' {
            $signatureEntry.object_reference.Remove('type')
            Test-Action1Signature -InputObject $signatureRequest | Should Be $false
            foreach ($invalid in @($null, '', ' ', 42, @('type'))) {
                $signatureEntry.object_reference.type = $invalid
                Test-Action1Signature -InputObject $signatureRequest | Should Be $false
            }
        }

        It 'requires both reference GUID fields' {
            foreach ($name in @('id', 'organization_id')) {
                $savedValue = $signatureEntry.object_reference[$name]
                $signatureEntry.object_reference.Remove($name)
                Test-Action1Signature -InputObject $signatureRequest | Should Be $false
                foreach ($invalid in @($null, '', ' ', 'malformed', 42, @('value'))) {
                    $signatureEntry.object_reference[$name] = $invalid
                    Test-Action1Signature -InputObject $signatureRequest | Should Be $false
                }
                $signatureEntry.object_reference[$name] = $savedValue
            }
        }

        It 'requires nonempty string alg, kid, and value fields' {
            foreach ($name in @('alg', 'kid', 'value')) {
                $savedValue = $signatureEntry.object_signature[$name]
                $signatureEntry.object_signature.Remove($name)
                Test-Action1Signature -InputObject $signatureRequest | Should Be $false
                foreach ($invalid in @($null, '', ' ', 42, @('value'), @{})) {
                    $signatureEntry.object_signature[$name] = $invalid
                    Test-Action1Signature -InputObject $signatureRequest | Should Be $false
                }
                $signatureEntry.object_signature[$name] = $savedValue
            }
        }

        It 'requires a positive integer timestamp and accepts Int64 JSON timestamps' {
            $signatureEntry.object_signature.Remove('iat')
            Test-Action1Signature -InputObject $signatureRequest | Should Be $false
            foreach ($invalid in @($null, '', '1795614034', 0, -1, 1.5, $true, @{})) {
                $signatureEntry.object_signature.iat = $invalid
                Test-Action1Signature -InputObject $signatureRequest | Should Be $false
            }
            $signatureEntry.object_signature.iat = [long]2147483648
            Test-Action1Signature -InputObject $signatureRequest | Should Be $true
        }

        It 'validates every entry in a multi-signature array' {
            $signatureRequest.signatures = @($signatureEntry, $signatureEntry)
            Test-Action1Signature -InputObject $signatureRequest | Should Be $true
            $signatureRequest.signatures = @($signatureEntry, @{})
            Test-Action1Signature -InputObject $signatureRequest | Should Be $false
        }

        It 'remains private' {
            (Get-Module PSAction1).ExportedFunctions.Keys -contains 'Test-Action1Signature' |
                Should Be $false
        }
    }
}
