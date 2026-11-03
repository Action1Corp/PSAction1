# Action1 API v4.0 PowerShell examples (Windows PowerShell 5.1)
# Configure action1_config.json before running. Signing is enabled by default.
$ErrorActionPreference = "Stop"
$action1ConfigFile = Join-Path $PSScriptRoot 'action1_config.json'

function Get-Action1Config {
    param([Parameter(Mandatory)][string]$Path)
    Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json
}

function Get-Action1Token {
    param([Parameter(Mandatory)]$Action1Config)
    $secret = (Get-Content -LiteralPath $Action1Config.api_secret_file -Raw -ErrorAction Stop).Trim()
    $body = @{ client_id = $Action1Config.api_key; client_secret = $secret }
    (Invoke-RestMethod -Uri "$($Action1Config.api_url)/oauth2/token" -Method Post -ContentType 'application/x-www-form-urlencoded' -Body $body -ErrorAction Stop).access_token
}

function Get-Action1Me {
    param($Action1Config, [string]$Token)
    Invoke-RestMethod -Uri "$($Action1Config.api_url)/me" -Method Get -Headers @{ Accept = 'application/json'; Authorization = "Bearer $Token" } -ErrorAction Stop
}


function Get-Action1SignTool {
    param($Action1Config)
    $signFile = $Action1Config.sign_file_name
    if (Test-Path -LiteralPath $signFile -PathType Leaf) { return $signFile }
    $destination = Split-Path -Path $signFile -Parent
    if (-not (Test-Path -LiteralPath $destination)) { New-Item -ItemType Directory -Path $destination -Force | Out-Null }
    $tempDir = Join-Path $env:TEMP ([guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    $zipFile = Join-Path $tempDir 'action1sign.zip'
    try {
        Invoke-WebRequest -Uri $Action1Config.sign_tool_url -OutFile $zipFile -UseBasicParsing -ErrorAction Stop
        $expectedHash = $Action1Config.sign_tool_sha256
        if ($expectedHash -notmatch '^[a-fA-F0-9]{64}$') { throw 'CRITICAL: Invalid SHA256 checksum file.' }
        $actualHash = (Get-FileHash -LiteralPath $zipFile -Algorithm SHA256).Hash
        if ($expectedHash -ne $actualHash) { throw "CRITICAL: SHA256 mismatch. Expected: $expectedHash, Actual: $actualHash" }
        Write-Host 'SHA256 verified.'
        $extractDir = Join-Path $tempDir 'extracted'
        Expand-Archive -LiteralPath $zipFile -DestinationPath $extractDir -ErrorAction Stop
        $fileName = Split-Path -Path $signFile -Leaf
        $extracted = Get-ChildItem -LiteralPath $extractDir -Filter $fileName -File -Recurse | Select-Object -First 1
        if (-not $extracted) { throw "Signing tool not found in ZIP: $fileName" }
        Copy-Item -LiteralPath $extracted.FullName -Destination $signFile -ErrorAction Stop
        return $signFile
    }
    finally { Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
}

function Get-Action1Automations {
    param($Action1Config, [string]$Token, [switch]$DebugRequest)
    $uri = "$($Action1Config.api_url)/automations/schedules/$($Action1Config.organization_id)"
    if ($DebugRequest) { Write-Host "GET $uri`nAccept: application/json`nAuthorization: Bearer <REDACTED>" }
    $response = Invoke-WebRequest -Uri $uri -Method Get -Headers @{ Accept = 'application/json'; Authorization = "Bearer $Token" } -UseBasicParsing -ErrorAction Stop
    if ($DebugRequest) { Write-Host "HTTP $($response.StatusCode)`n$($response.Content)" }
    $response.Content | ConvertFrom-Json
}

# Signs an Action1 configuration using temporary files for input and output
function Get-Action1SignatureEx {
    param($Action1Config, $Configuration)
    $tempDir = Join-Path $env:TEMP ([guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    $configFile = Join-Path $tempDir 'configuration.json'
    $signatureFile = Join-Path $tempDir 'signature.json'
    try {
        $json = $Configuration | ConvertTo-Json -Depth 20
        [System.IO.File]::WriteAllText($configFile, $json, (New-Object System.Text.UTF8Encoding($false)))
        $output = & $Action1Config.sign_file_name "--config=$configFile" "--action1-key=$($Action1Config.key_file)" "--passphrase-file=$($Action1Config.passphrase_file)" "--out=$signatureFile" 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Action1Sign failed: $($output -join ' ')" }
        if (-not (Test-Path -LiteralPath $signatureFile -PathType Leaf)) { throw 'Action1Sign did not create signature.json.' }
        Get-Content -LiteralPath $signatureFile -Raw | ConvertFrom-Json
    }
    finally { Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
}

# Signs an Action1 configuration using pipes for input and output
function Get-Action1Signature {
    param($Action1Config, $Configuration)
    $json = $Configuration | ConvertTo-Json -Depth 20
    $output = $json | & $Action1Config.sign_file_name "--config=-" "--action1-key=$($Action1Config.key_file)" "--passphrase-file=$($Action1Config.passphrase_file)" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Action1Sign failed: $($output -join ' ')" }
    $output | ConvertFrom-Json
}

function New-Action1EndpointScope {
    param([string[]]$EndpointGroups = @(), [string[]]$Endpoints = @(), [switch]$All)
    $scope = @()
    if ($All) { $scope += @{ id = 'ALL'; type = 'EndpointGroup' } }
    foreach ($id in $EndpointGroups) { $scope += @{ id = $id; type = 'EndpointGroup' } }
    foreach ($id in $Endpoints) { $scope += @{ id = $id; type = 'Endpoint' } }
    if ($scope.Count -eq 0) { throw 'Specify -All, -EndpointGroups, or -Endpoints.' }
    return ,$scope
}

function Get-Action1Scheduler {
    param(
        [ValidateSet('Disabled', 'RunNow', 'Once')]
        [string]$Schedule = 'Disabled',
        [Nullable[datetime]]$StartTime = $null
    )

    $settings = @{}

    switch ($Schedule) {
        'Disabled' {
            $settings.settings = 'DISABLED'
        }
        'RunNow' {
            $settings.start_time = [datetime]::UtcNow.AddMinutes(1).ToString('yyyy-MM-dd_HH-mm-ss')
        }
        'Once' {
           if ($null -eq $StartTime) {
                throw 'StartTime is required for -Schedule Once.'
            }
            $settings.settings = "ENABLED ONCE AT:$($StartTime.ToString('HH-mm-ss')) DATE:$($StartTime.ToString('yyyy-MM-dd'))"
            $settings.settings_timezone = 'UTC'
        }
    }

    return $settings
}

function New-Action1RunScriptConfiguration {
    param($Action1Config, [string]$Name, [string]$Script, [int]$RetryMinutes = 10,
          [ValidateSet('Disabled', 'RunNow', 'Once')][string]$Schedule = 'Disabled', [datetime]$StartTime)
    $configuration = @{
        id = [guid]::NewGuid().ToString()
        type = 'AutomationScheduleConfiguration'
        organization_id = $Action1Config.organization_id
        name = $Name
        retry_minutes = "$RetryMinutes"
        actions = @(@{
            id = [guid]::NewGuid().ToString(); name = 'Run PowerShell'; template_id = 'run_script'
            params = @{
                run_script_params = @();
                run_script_text = $Script;
                run_script_language = 'PowerShell';
                reboot_options = @{auto_reboot = 'no'}
            }
        })
    }
    
    $configuration += Get-Action1Scheduler -Schedule $Schedule -StartTime $StartTime
    return $configuration
}

function New-Action1Automation {
    param($Action1Config, [string]$Token, $Configuration, [array]$Scope, [bool]$Sign = $true,
          [ValidateSet('Disabled', 'RunNow', 'Once')][string]$Schedule = 'Disabled', [switch]$DebugRequest)
    $request = @{ endpoints = $Scope; configuration = $Configuration }
    if ($Sign) {
        $signature = Get-Action1Signature -Action1Config $Action1Config -Configuration $Configuration
        $request.signatures = @(@{
            object_reference = @{
                id = $Configuration.id; organization_id = $Action1Config.organization_id
                type = 'AutomationScheduleConfiguration'
            }
            object_signature = $signature;
        })
    }
    $body = $request | ConvertTo-Json -Depth 20

    $path = if ($Schedule -eq 'RunNow') { 'automations/instances' } else { 'automations/schedules' }
    $uri = "$($Action1Config.api_url)/$path/$($Action1Config.organization_id)"
    $headers = @{ Accept = 'application/json'; Authorization = "Bearer $Token" }
    if ($DebugRequest) {
        Write-Host "-= HTTP REQUEST =-`nPOST $uri`nContent-Type: application/json`nAccept: application/json`nAuthorization: Bearer <REDACTED>`n$body`n=-"
    }
    try {
        $response = Invoke-WebRequest -Uri $uri -Method Post -Headers $headers -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes($body)) -UseBasicParsing -ErrorAction Stop
        if ($DebugRequest) { Write-Host "HTTP $($response.StatusCode)`n$($response.Content)" }
        return $Configuration.id
    }
    catch {
        Write-Host 'ERROR: Failed to create automation.' -ForegroundColor Red
        if ($_.Exception.Response) {
            $errorResponse = $_.Exception.Response
            Write-Host "HTTP Status: $([int]$errorResponse.StatusCode)"
            $stream = $errorResponse.GetResponseStream()
            if ($stream) {
                $reader = New-Object System.IO.StreamReader($stream)
                try { Write-Host "Response: $($reader.ReadToEnd())" }
                finally { $reader.Dispose() }
            }
        }
        throw
    }
}

# Public entry point for disabled, run-now, and one-time scheduled PowerShell automations.
function New-Action1PowerShellAutomation {
    param(
        $Action1Config, [string]$Token, [string]$Name, [string]$Script, [int]$RetryMinutes = 10,
        [string[]]$EndpointGroups = @(), [string[]]$Endpoints = @(), [switch]$All,
        [ValidateSet('Disabled', 'RunNow', 'Once')][string]$Schedule = 'Disabled',
        [datetime]$StartTime, [bool]$Sign = $true, [switch]$DebugRequest
    )
    $scope = New-Action1EndpointScope -EndpointGroups $EndpointGroups -Endpoints $Endpoints -All:$All
    $params = @{ Action1Config = $Action1Config; Name = $Name; Script = $Script; RetryMinutes = $RetryMinutes; Schedule = $Schedule }
    if ($PSBoundParameters.ContainsKey('StartTime')) { $params.StartTime = $StartTime }
    $configuration = New-Action1RunScriptConfiguration @params
    New-Action1Automation -Action1Config $Action1Config -Token $Token -Configuration $configuration -Scope $scope -Sign $Sign -Schedule $Schedule -DebugRequest:$DebugRequest
}

# Example usage (uncomment after updating action1_config.json):
$action1_config = Get-Action1Config -Path $action1ConfigFile
Get-Action1SignTool -Action1Config $action1_config | Out-Null
$token = Get-Action1Token -Action1Config $action1_config
$me = Get-Action1Me -Action1Config $action1_config -Token $token
$id = New-Action1PowerShellAutomation -Action1Config $action1_config -Token $token -Name 'Get Local Date' -Script 'Get-Date' -All
$id = New-Action1PowerShellAutomation -Action1Config $action1_config -Token $token -Name 'Get Local Date Now' -Script 'Get-Date' -Endpoints @("0920a6f4-fa6e-4f65-bce6-4b1c714dee52") -Schedule RunNow
$id = New-Action1PowerShellAutomation -Action1Config $action1_config -Token $token -Name 'Get Local Date' -Script 'Get-Date' -All -Schedule Once -StartTime ([datetime]::UtcNow.AddMinutes(10))
Get-Action1Automations -Action1Config $action1_config -Token $token | ConvertTo-Json -Depth 2
