# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

# Offline signing-tool simulation. Accepts CLI-style arguments and pipeline input.
# It does not perform cryptographic signing or test native stdin/stderr encoding.
$configPath = $null
$keyPath = $null
$stdinPassphrase = $false
foreach ($argument in $args) {
    if ($argument.StartsWith('--config=')) {
        $configPath = $argument.Substring(9)
    }
    elseif ($argument.StartsWith('--action1-key=')) {
        $keyPath = $argument.Substring(14)
    }
    elseif ($argument -eq '--passphrase-file=-') {
        $stdinPassphrase = $true
    }
    else {
        exit 41
    }
}
if ([string]::IsNullOrWhiteSpace($configPath) -or
    [string]::IsNullOrWhiteSpace($keyPath) -or -not $stdinPassphrase) {
    exit 42
}

# Test keys contain only a fixture mode; the pipeline carries a synthetic secret.
$mode = (Get-Content -LiteralPath $keyPath -Raw -ErrorAction Stop).Trim()
$pipelineValues = @($input)
$expectedPassphrase = 'synthetic-p' + [char]0xE4 + 'ss-' + [char]0x3A9
if ($pipelineValues.Count -ne 1 -or $pipelineValues[0] -cne $expectedPassphrase) {
    exit 43
}
if ($global:OutputEncoding.CodePage -ne 65001 -or
    [Console]::OutputEncoding.CodePage -ne 65001) {
    exit 45
}
$configBytes = [IO.File]::ReadAllBytes($configPath)
$utf8 = New-Object Text.UTF8Encoding($false, $true)
$configJson = $utf8.GetString($configBytes)
if ($configJson.StartsWith([string][char]0xFEFF, [StringComparison]::Ordinal)) {
    exit 44
}

# Capture only configuration bytes and path, never the passphrase.
[IO.File]::WriteAllBytes($keyPath + '.config', $configBytes)
[IO.File]::WriteAllText($keyPath + '.path', $configPath)

switch ($mode) {
    'exit' {
        Write-Error 'synthetic-secret-diagnostic' -ErrorAction Continue
        'synthetic-secret-output'
        exit 23
    }
    'malformed' { '{broken-json' }
    'empty' { '{}' }
    'array' { '[{"alg":"EdDSA"}]' }
    'null' { 'null' }
    'silent' { }
    default {
        Write-Error 'synthetic-secret-diagnostic' -ErrorAction Continue
        '{"alg":"EdDSA","iat":1795614034,"kid":"synthetic-key","value":"synthetic-signature"}'
    }
}

# An explicit script exit code simulates the native executable's LASTEXITCODE.
exit 0
