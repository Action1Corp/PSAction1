# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

# Windows PowerShell 5.1 / Pester 3.4 or later. No real keys or network calls.
# The script fixture simulates tool I/O and exit codes, not native stream encoding.
$modulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'PSAction1.psd1'
Import-Module $modulePath -Force -ErrorAction Stop
InModuleScope PSAction1 {
    Describe 'New-Action1Signature' {
        $fixtureSource = Join-Path $script:ModuleRoot 'Tests\Fixtures\SigningTool.ps1'
        $fixturePath = Join-Path $TestDrive 'Synthetic Signing Tool.ps1'
        Copy-Item -LiteralPath $fixtureSource -Destination $fixturePath -ErrorAction Stop

        BeforeEach {
            $script:savedSigningState = @{
                ToolPath = $script:Action1_SignToolPath
                ToolName = $script:Action1_SignToolFileName
                KeyPath = $script:Action1_SignKeyPath
                Passphrase = $script:Action1_SignPassphrase
            }
            $script:savedInputEncoding = $global:OutputEncoding
            $script:savedConsoleEncoding = [Console]::OutputEncoding
            $script:Action1_SignToolPath = $TestDrive
            $script:Action1_SignToolFileName = 'Synthetic Signing Tool.ps1'
            $keyName = 'synthetic key ' + (New-Guid).Guid + '.txt'
            $script:Action1_SignKeyPath = Join-Path $TestDrive $keyName
            Set-Content -LiteralPath $script:Action1_SignKeyPath -Value success
            $syntheticSecret = 'synthetic-p' + [char]0xE4 + 'ss-' + [char]0x3A9
            $script:Action1_SignPassphrase = New-Object Security.SecureString
            foreach ($character in $syntheticSecret.ToCharArray()) {
                $script:Action1_SignPassphrase.AppendChar($character)
            }
            $script:Action1_SignPassphrase.MakeReadOnly()
            $script:signingConfig = [ordered]@{
                id = '11111111-1111-1111-1111-111111111111'
                type = 'SyntheticConfiguration'
                organization_id = '22222222-2222-2222-2222-222222222222'
                name = 'Unicode ' + [char]0x3A9
                nested = @{ values = @(1, 2); enabled = $true }
            }
            Mock Test-Action1SignTool { $true }
            Mock Invoke-WebRequest { throw 'Tests must not call the network.' }
            Mock Invoke-Action1ApiRequest { throw 'Tests must not call the API.' }
        }

        AfterEach {
            $script:Action1_SignToolPath = $savedSigningState.ToolPath
            $script:Action1_SignToolFileName = $savedSigningState.ToolName
            $script:Action1_SignKeyPath = $savedSigningState.KeyPath
            $script:Action1_SignPassphrase = $savedSigningState.Passphrase
            $global:OutputEncoding = $savedInputEncoding
            [Console]::OutputEncoding = $savedConsoleEncoding
        }

        It 'returns one parsed signature using session credentials and Unicode pipeline input' {
            $result = @(New-Action1Signature -ObjectConfig $signingConfig)
            $result.Count | Should Be 1
            ($result[0] -is [pscustomobject]) | Should Be $true
            $result[0].alg | Should Be EdDSA
            $result[0].iat | Should Be 1795614034
            $result[0].kid | Should Be synthetic-key
            $result[0].value | Should Be synthetic-signature
            $configJson = [IO.File]::ReadAllText($script:Action1_SignKeyPath + '.config')
            $configJson | Should Be (ConvertTo-Json $signingConfig -Depth 100 -Compress)
            $configPath = [IO.File]::ReadAllText($script:Action1_SignKeyPath + '.path')
            Test-Path -LiteralPath $configPath | Should Be $false
            [object]::ReferenceEquals($global:OutputEncoding, $savedInputEncoding) |
                Should Be $true
            [Console]::OutputEncoding.CodePage | Should Be $savedConsoleEncoding.CodePage
            Assert-MockCalled Test-Action1SignTool -Times 1 -Exactly -Scope It
            Assert-MockCalled Invoke-WebRequest -Times 0 -Exactly -Scope It
            Assert-MockCalled Invoke-Action1ApiRequest -Times 0 -Exactly -Scope It
        }

        It 'accepts explicit credentials without changing session credentials' {
            $explicitKey = Join-Path $TestDrive 'explicit key.txt'
            Set-Content -LiteralPath $explicitKey -Value success
            $result = New-Action1Signature -ObjectConfig ([pscustomobject]$signingConfig) `
                -Action1KeyPath $explicitKey -Passphrase $script:Action1_SignPassphrase
            $result.value | Should Be synthetic-signature
            Test-Path -LiteralPath ($explicitKey + '.config') | Should Be $true
            $script:Action1_SignKeyPath | Should Not Be $explicitKey
        }

        It 'accepts a JSON Count property without confusing it with dictionary size' {
            $result = New-Action1Signature -ObjectConfig @{ Count = 0 }
            $result.value | Should Be synthetic-signature
        }

        It 'signs and attaches a configuration through both helpers using the script fixture' {
            $signingConfig.Remove('id')
            $request = [pscustomobject]@{
                configuration = [pscustomobject]$signingConfig
                endpoints = @(@{ id = 'synthetic-target'; type = 'Endpoint' })
            }
            $body = Add-Action1Signature -InputObject $request
            $configJson = [IO.File]::ReadAllText($script:Action1_SignKeyPath + '.config')
            $serializedConfiguration = ConvertFrom-Json $configJson
            Test-Guid -Guid $serializedConfiguration.id | Should Be $true
            $serializedConfiguration.id | Should Be $body.configuration.id
            $body.signatures[0].object_reference.id | Should Be $serializedConfiguration.id
            $body.signatures[0].object_signature.value | Should Be synthetic-signature
            $serializedConfiguration.PSObject.Properties.Name -contains 'signatures' |
                Should Be $false
        }

        It 'rejects null, scalar, array, and empty object inputs before tool validation' {
            foreach ($invalid in @($null, '', '{}', 42, @('value'), @{}, [pscustomobject]@{})) {
                { New-Action1Signature -ObjectConfig $invalid } | Should Throw
            }
            Assert-MockCalled Test-Action1SignTool -Times 0 -Exactly -Scope It
        }

        It 'rejects missing, whitespace, directory, and empty key paths' {
            $emptyKey = Join-Path $TestDrive 'empty.key'
            $null = New-Item -Path $emptyKey -ItemType File -Force
            foreach ($invalid in @($null, '', ' ', (Join-Path $TestDrive 'missing.key'),
                $TestDrive, $emptyKey)) {
                {
                    New-Action1Signature -ObjectConfig $signingConfig -Action1KeyPath $invalid
                } | Should Throw
            }
            Assert-MockCalled Test-Action1SignTool -Times 0 -Exactly -Scope It
        }

        It 'stops on tool validation failure before inspecting a missing passphrase' {
            Mock Test-Action1SignTool { $false }
            {
                New-Action1Signature -ObjectConfig $signingConfig -Passphrase $null
            } | Should Throw 'Action1 signing tool validation failed.'
            Test-Path -LiteralPath ($script:Action1_SignKeyPath + '.config') |
                Should Be $false
        }

        It 'rejects null and empty SecureString passphrases after validating the tool' {
            foreach ($invalid in @($null, (New-Object Security.SecureString))) {
                {
                    New-Action1Signature -ObjectConfig $signingConfig -Passphrase $invalid
                } | Should Throw 'Set-Action1Sign'
            }
            Assert-MockCalled Test-Action1SignTool -Times 2 -Exactly -Scope It
        }

        It 'rejects plaintext passphrases' {
            {
                New-Action1Signature -ObjectConfig $signingConfig -Passphrase 'synthetic'
            } | Should Throw
        }

        It 'sanitizes a simulated tool failure and cleans up configuration and encodings' {
            Set-Content -LiteralPath $script:Action1_SignKeyPath -Value exit
            $failure = $null
            try { New-Action1Signature -ObjectConfig $signingConfig }
            catch { $failure = $_ }
            $failure.Exception.Message | Should Be 'Action1 signing tool failed with exit code 23.'
            $failure.Exception.Message | Should Not Match 'synthetic-secret'
            $configPath = [IO.File]::ReadAllText($script:Action1_SignKeyPath + '.path')
            Test-Path -LiteralPath $configPath | Should Be $false
            [object]::ReferenceEquals($global:OutputEncoding, $savedInputEncoding) |
                Should Be $true
            [Console]::OutputEncoding.CodePage | Should Be $savedConsoleEncoding.CodePage
        }

        It 'rejects malformed, empty, array, null, and missing output and removes each temp file' {
            foreach ($mode in @('malformed', 'empty', 'array', 'null', 'silent')) {
                Set-Content -LiteralPath $script:Action1_SignKeyPath -Value $mode
                { New-Action1Signature -ObjectConfig $signingConfig } | Should Throw
                $configPath = [IO.File]::ReadAllText($script:Action1_SignKeyPath + '.path')
                Test-Path -LiteralPath $configPath | Should Be $false
                [Console]::OutputEncoding.CodePage | Should Be $savedConsoleEncoding.CodePage
            }
        }

        It 'rejects an unresolved tool path' {
            $script:Action1_SignToolFileName = 'missing.ps1'
            { New-Action1Signature -ObjectConfig $signingConfig } | Should Throw
        }
    }
}
