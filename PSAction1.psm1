# Name: PSAction1
# Description: Powershell module for working with the Action1 API.

# Documentation: https://github.com/Action1Corp/PSAction1/
# Use Action1 Roadmap system (https://roadmap.action1.com/) to submit feedback or enhancement requests.

# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

$Script:Action1_APIKey
$Script:Action1_Secret
$Script:Action1_Token
$script:Action1_Hosts = [ordered]@{
    NorthAmerica = 'https://app.action1.com/api/3.0'; 
    Europe = 'https://app.eu.action1.com/api/3.0'; 
    Australia = 'https://app.au.action1.com/api/3.0'
}
$Script:Action1_BaseURI = ''
$Script:Action1_Default_Org
$Script:Action1_DebugEnabled = $false
$Script:Action1_Interactive = $false
$Script:Action1_CVE_Lookup = @{}

$Script:Action1_429RetryBaseTimeout = 2000

$URILookUp = @{
    G_AdvancedSettings     = { param($Org_ID) "/setting_templates/$Org_ID" }
    G_AgentDeployment      = { param($Org_ID) "/endpoints/discovery/$Org_ID" }
    G_Apps                 = { param($Org_ID) "/apps/$Org_ID/data" }
    G_AutomationInstances  = { param($Org_ID, $Object_ID) "/automations/instances/$Org_ID`?endpoint_id=$Object_ID" }
    G_Automations          = { param($Org_ID) "/policies/schedules/$Org_ID" }
    G_Endpoint             = { param($Org_ID, $Object_ID) "/endpoints/managed/$Org_ID/$Object_ID" }
    G_Endpoints            = { param($Org_ID) "/endpoints/managed/$Org_ID" }
    G_EndpointApps         = { param($Org_ID, $Object_ID) "/apps/$Org_ID/data/$Object_ID" }
    G_EndpointGroupMembers = { param($Org_ID, $Object_ID)"/endpoints/groups/$Org_ID/$Object_ID/contents" }
    G_EndpointGroups       = { param($Org_ID) "/endpoints/groups/$Org_ID" }
    G_Logs                 = { param($Org_ID) "/logs/$Org_ID" }
    G_Me                   = { "/Me" }
    G_MissingUpdates       = { param($Org_ID) "/updates/$Org_ID" }
    G_Organizations        = { "/organizations" }
    G_Packages             = { "/packages/all" }
    G_PackageVersions      = { param($Object_ID) "/software-repository/all/$Object_ID`?fields=versions" }
    G_Policy               = { param($Org_ID, $Object_ID) "/policies/instances/$Org_ID/$Object_ID" }
    G_Policies             = { param($Org_ID)  "/policies/instances/$Org_ID" }
    G_PolicyResults        = { param($Org_ID, $Object_ID) "/policies/instances/$Org_ID/$Object_ID/endpoint_results" }
    G_ReportData           = { param($Org_ID, $Object_ID)"/reportdata/$Org_ID/$Object_ID/data" }
    G_ReportExport         = { param($Org_ID, $Object_ID)"/reportdata/$Org_ID/$Object_ID/export" }
    G_Reports              = { "/reports/all" } 
    G_Scripts              = { "/scripts/all" } 
    G_Vulnerabilities      = { param($Org_ID) "/Vulnerabilities/$Org_ID" }
    N_Automation           = { param($Org_ID)  "/policies/schedules/$Org_ID" }
    N_EndpointGroup        = { param($Org_ID) "/endpoints/groups/$Org_ID" }
    N_Organization         = { "/organizations" }
    N_Remediation          = { param($Org_ID)  "/policies/instances/$Org_ID" }
    N_DeferredRemediation  = { param($Org_ID)  "/policies/schedules/$Org_ID" }
    N_DeploySoftware       = { param($Org_ID)  "/policies/instances/$Org_ID" }
    R_ReportData           = { param($Org_ID, $Object_ID) "/reportdata/$Org_ID/$Object_ID/requery" }
    R_InstalledSoftware    = { param($Org_ID, $Object_ID) "/apps/$Org_ID/requery/$Object_ID" }
    R_InstalledUpdates     = { param($Org_ID) "/updates/installed/$Org_ID/requery" }
    U_Endpoint             = { param($Org_ID, $Object_ID) "/endpoints/managed/$Org_ID/$Object_ID" }
    U_GroupModify          = { param($Org_ID, $Object_ID) "/endpoints/groups/$Org_ID/$Object_ID" }
    U_GroupMembers         = { param($Org_ID, $Object_ID) "/endpoints/groups/$Org_ID/$Object_ID/contents" }
    U_Automation           = { param($Org_ID, $Object_ID)  "/policies/schedules/$Org_ID/$Object_ID" }
}

#----------------------------------JSON object templates---------------------------------------

$RemediationTemplate = @"
{
  "name": "",
  "retry_minutes": "1440",
  "endpoints": [
    {
      "id": "ALL",
      "type": "EndpointGroup"
    }
  ],
  "actions": [
    {
      "name": "Deploy Update",
      "template_id": "deploy_update",
      "params": {
        "display_summary": "",
        "packages": [
          {
            "default": "default"
          }
        ],
        "update_approval": "manual",
        "automatic_approval_delay_days": 7,
        "scope": "Specified",
        "reboot_options": {
          "auto_reboot": "yes",
          "show_message": "yes",
          "message_text": "Your computer requires maintenance and will be rebooted. Please save all work and reboot now to avoid losing any data.",
          "timeout": 240
        }
      }
    }
  ]
}
"@

$PackageDeployTemplate = @"
{
  "name": "",
  "retry_minutes": "1440",
  "endpoints": [
    {
      "id": "ALL",
      "type": "EndpointGroup"
    }
  ],
 "actions": [
    {
      "name": "Deploy Software",
      "template_id": "deploy_package",
      "params": {
        "display_summary": "",
        "packages": [
          {
            "default": "default"
          }
        ],
        "reboot_options": {
          "auto_reboot": "no"
        }
      }
    }
  ]
}
"@
#----------------------------------JSON object templates---------------------------------------

function Initialize-Action1Token {
    [CmdletBinding()]
    param()

    if (
        ($null -ne $Script:Action1_Token) -and
        ($null -ne $Script:Action1_Token.access_token) -and
        ($Script:Action1_Token.expires_at -ge (Get-Date))
    ) {
        Debug-Host "Current token is valid."
        return $true
    }

    Debug-Host "Token not set or expired, fetching new token."

    $token = Request-Action1Token

    if ($null -ne $token) {
        $Script:Action1_Token = $token
        Debug-Host "Token refresh successful."
        return $true
    }

    Write-Error "Token could not be refreshed, check for errors in output."
    return $false
}

function Initialize-Action1Region {
    [CmdletBinding()]
    param()

    if (-not [string]::IsNullOrWhiteSpace($Script:Action1_BaseURI)) {
        return $true
    }

    if (-not $Script:Action1_Interactive) {
        throw "Region not set. Call Set-Action1Region prior to making API calls."
    }

    $regions = @($Script:Action1_Hosts.GetEnumerator())

    while ([string]::IsNullOrWhiteSpace($Script:Action1_BaseURI)) {

        for ($i = 0; $i -lt $regions.Count; $i++) {
            Write-Host "$i : $($regions[$i].Key)"
        }

        $selection = Read-Host -Prompt 'Select your data center region'

        $index = 0
        if (
            [int]::TryParse($selection, [ref]$index) -and
            $index -ge 0 -and
            $index -lt $regions.Count
        ) {
            $Script:Action1_BaseURI = $regions[$index].Value
        }
        else {
            Write-Warning "Invalid selection."
        }
    }
    return $true
}

function Initialize-Action1DefaultOrg {
    [CmdletBinding()]
    param()

    if ($null -eq $Script:Action1_Default_Org) {
        if ($Script:Action1_Interactive) {
            Set-Action1DefaultOrg

            if ($null -eq $Script:Action1_Default_Org) {
                throw "Default organization was not selected."
            }
        }
        else {
            throw "Default Org not set. Call Set-Action1DefaultOrg before making API calls."
        }
    }
    return $Script:Action1_Default_Org
}

function Request-Action1Token {
    [CmdletBinding()]
    param()

    if (Initialize-Action1Region) {
        if ([string]::IsNullOrEmpty($Script:Action1_APIKey) -or [string]::IsNullOrEmpty($Script:Action1_Secret)) {
            if ($Script:Action1_Interactive) {
                Set-Action1Credentials 
            }
            else { 
                Write-Error "Authentication details are not set, call Set-Action1Credentials prior to making any calls to the API."
                exit
            } 
        }
        try {
            $Token = Invoke-Action1ApiRequest `
                -Method POST `
                -Path "$Script:Action1_BaseURI/oauth2/token" `
                -Label 'Request OAuth2 token' `
                -Body @{
                    client_id     = $Script:Action1_APIKey
                    client_secret = $Script:Action1_Secret
                } `
                -SkipAuthenticationCheck
            $Token | Add-Member -MemberType NoteProperty -Name "expires_at" -Value $(Get-Date).AddSeconds(([int]$Token.expires_in - 5)) #Expire token 5 seconds early to avoid race condition timeouts.
            return $Token
        }
        catch [System.Net.WebException] {
            Write-Error "Error fetching auth token: $($_)."
            Write-Error $Token
            return $null
        }     
    }
}

function Join-QueryString {
    param(
        [string]$QueryString,
        [string]$Argument
    )

    if ($QueryString) {
        "$QueryString&$Argument"
    }
    else {
        $Argument
    }
}

function Invoke-Action1ApiRequest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
        [string]$Method,
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Label,
        [hashtable]$Headers,
        [object]$Body,
        [switch]$RawBody,
        [string]$AddArgs,
        [switch]$RawResponse,
        [switch]$SkipAuthenticationCheck
    )

    if ($AddArgs) {
        $Path += "?{0}" -f $AddArgs
    }

    $headers = @{}

    if (-not $SkipAuthenticationCheck) {
        if (Initialize-Action1Token) {
            $headers.Authorization = "Bearer $($Script:Action1_Token.access_token)"
        }
    }

    $headers['Content-Type'] = 'application/json; charset=utf-8'

    if ($Headers) {
        foreach ($key in @($Headers.Keys)) {
            $headers[$key] = $Headers[$key]
        }
    }

    $requestBody = $null

    if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
        if ($RawBody) {
            $requestBody = $Body
            Debug-Host "Raw request body supplied. Type: $($requestBody.GetType().FullName)"
        }
        else {
            $requestBody = ConvertTo-Json -InputObject $Body -Depth 10
            Debug-Host "JSON Data to be sent:`n$requestBody"  
        }
    }

    $invokeWebRequestParams = @{
        Uri             = $Path
        Method          = $Method
        UseBasicParsing = $true
        Headers         = $headers
        ErrorAction     = 'Stop'
    }

    if ($null -ne $requestBody) {
        $invokeWebRequestParams.Body = $requestBody
    }

    $retry429Count = 0

    while ($true) {
        Debug-Host "$Method request to $Path. RawResponse flag is $RawResponse"
        try {
            if($Script:Action1_DebugEnabled){$webRequestSW = [System.Diagnostics.Stopwatch]::StartNew()}

            $response = Invoke-WebRequest @invokeWebRequestParams

            if($Script:Action1_DebugEnabled){
                $webRequestSW.Stop()
                Debug-Host ("{2} request to {0} took {1}ms" -f $Path, $($webRequestSW.ElapsedMilliseconds), $Method)
            }

            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
                Debug-Host ("Success response code {0} for {1} to {2}" -f $($response.StatusCode), $Method, $Path)
                if ($RawResponse) {
                    return $response.Content
                }

                if ([string]::IsNullOrWhiteSpace($response.Content)) {
                    return $null
                }

                return ConvertFrom-Json -InputObject $response.Content
            }

            Debug-Host "Error processing $($Label): HTTP status code $($response.StatusCode)."
            return $null
        }
        catch {
            $statusCode = $null

            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            Debug-Host ("Failed response code {0} for {1} to {2}" -f $statusCode, $Method, $Path)

            if ($statusCode -eq 429) {
                
                $retryTimeout = [Math]::Pow(2,$retry429Count) * $Script:Action1_429RetryBaseTimeout
                $retry429Count++

                Debug-Host ("429 received for '{0}'. Retry #{1}. Sleeping {2} ms." -f $Label, $retry429Count, $retryTimeout)
                Start-Sleep -Milliseconds $retryTimeout
                continue
            }

            Debug-Host "Error processing $($Label): $($_.Exception.Message)"
            return $null
        }
    }
}

function Start-Action1PackageUpload {
    param(
        [Parameter(Mandatory)]
        [String]$Package_ID,
        [Parameter(Mandatory)]
        [String]$Version_ID,
        [Parameter(Mandatory)]
        [String]$Filename,
        [Parameter(Mandatory)]
        [ValidateSet(
            'Windows_32',
            'Windows_64'
        )]
        [String]$Platform,
        [int32]$BufferSize = 24Mb
    )
    $uri = "$Script:Action1_BaseURI/software-repository/all/$Package_ID/versions/$Version_ID/upload?platform=$Platform" 
    Debug-Host "Base URI is $uri"
    $UploadTarget = ""
    Debug-Host "Uploading file: '$Filename'"
    Debug-Host "Writing in chunks of $BufferSize bytes."
    $FileData = [System.IO.File]::Open($Filename, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
    if ($FileData.Length -lt $BufferSize) {
         $BufferSize = $FileData.Length; 
         Debug-Host "File is smaller than BufferSize, adjusting to $($FileData.Length)" 
    }
    $Buffer = New-Object byte[] $BufferSize
    $Place = 0

    $HeaderBase = @{
        'accept'                = '*/*'
        'X-Upload-Content-Type' = 'application/octet-stream'
    }

    try {
        $Headers = $HeaderBase.Clone()
        $Headers.Add('X-Upload-Content-Length', $($FileData.Length))
        Invoke-Action1ApiRequest -Method POST -Path $uri -Label 'Opening upload stream' -Headers $Headers -ErrorAction SilentlyContinue  
    }
    catch { 
        $UploadTarget = $_.Exception.Response.Headers['X-Upload-Location'] 
    } 

    Debug-Host "Upload URI is $UploadTarget"

    while (($Read = $FileData.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
        $Headers = $HeaderBase.Clone()
        $Headers.Add('Content-Range', "bytes $($Place)-$($($Place + $Read-1))/$($FileData.Length)")
        $Headers.Add('Content-Length', "$($Read)")
        $Headers.Add('Content-Type', 'application/octet-stream')
        $Place += $Read
        try { 
            $response = Invoke-Action1ApiRequest `
                -Method PUT `
                -Path $UploadTarget `
                -Label "Uploading Package $($Package_ID)" `
                -Body $Buffer `
                -RawBody `
                -Headers $Headers `
                -ErrorAction SilentlyContinue         
        }
        catch {
            Debug-Host "Last Status: $($_.Exception.Response.StatusCode)" 
        }

        if (($FileData.Length - $Place) -lt $BufferSize) { 
            $buffer = New-Object byte[] ($FileData.Length - $place) 
        }
        Debug-Host "Upload $([math]::Round((($Place / $FileData.Length)*100),1))% Complete."

        if ($Buffer.Length -eq 0) { 
            Debug-Host "Final Status:$($response.StatusCode)" 
        }
        else {
            Debug-Host "Bytes Written: $($Buffer.Length)" 
        }
    }
    $FileData.Close()
}


function Debug-Host {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )
    if ($Script:Action1_DebugEnabled) { Write-Host "Action1 Debug: $Message" -ForegroundColor Blue }
}

function Set-Action1Credentials {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$APIKey,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Secret
    )
    $Script:Action1_APIKey = $APIKey
    $Script:Action1_Secret = $Secret
}

function Set-Action1Debug {
    param(
        [Parameter(Mandatory)]
        [boolean]$Enabled
    )
    $Script:Action1_DebugEnabled = $Enabled
    if ($Enabled) { Debug-Host "Debugging enabled." }
}

function Set-Action1DefaultOrg {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Org_ID
    )
    $Script:Action1_Default_Org = $Org_ID
}

function Set-Action1Locale {
    [Obsolete("Please use Set-Action1Region instead.")]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('NorthAmerica', 'Europe', 'Australia')]
        [String]$Region
    )
    Set-Action1Region -Region $Region
}

function Set-Action1Region {
    param (
        [Parameter(Mandatory)]
        [ValidateSet('NorthAmerica', 'Europe', 'Australia')]
        [String]$Region
    )
    $Script:Action1_BaseURI = $Script:Action1_Hosts[$Region]
}

function Set-Action1Interactive {
    param(
        [Parameter(Mandatory)]
        [boolean]$Enabled
    )
    if ($Enabled) { Debug-Host "Interactive mode enabled, you will be prompted for variables that are required but not set." }
    $Script:Action1_Interactive = $Enabled
}

function Get-Action1 {
    param (
        [Parameter(Mandatory)]
        [ValidateSet(   
            'AutomationInstances',
            'Automations',
            'AdvancedSettings',
            'Apps',
            'CustomAttribute',
            'EndpointGroupMembers',
            'EndpointGroups',
            'Me',
            'Endpoint',
            'EndpointApps',
            'Endpoints',
            'Logs',
            'MissingUpdates',
            'Organizations',
            'Packages',
            'PackageVersions',
            'Policy',
            'Policies',
            'PolicyResults',
            'ReportData',
            'ReportExport',
            'Reports',
            'Scripts',
            'AgentDeployment',
            'Vulnerabilities',
            'RawURI',
            'Settings'
        )]
        [String]$Query,
        [string]$Id,
        [int]$Limit,
        #[int]$From,
        [string]$URI,
        [ValidateSet(
            'Automation',
            'Endpoint',
            'EndpointGroup',
            'Organization',
            'GroupAddEndpoint',
            'GroupDeleteEndpoint',
            'GroupFilter',
            'Remediation',
            'DeferredRemediation',
            'DeploySoftware'
        )]
        [string]$For,
        [string]$Clone
    )
    #Short out processing path if URI literal is specified.
    if ($Query -eq 'RawURI') {
         if (!$URI) {
             Write-Error "Error -URI value required when Query is type RawURI.`n"; 
             return $null 
        }
        else {
             return Invoke-Action1ApiRequest -Method GET -Path $URI -Label $Query 
        } 
    }
    # Retrieve settings objects for post/patch actions.
    if ($Query -eq 'Settings') {
        if (!$For) { 
            Write-Error "Error: -For value must be specified when Query type is 'Settings'.`n"; return $null 
        }
        else { 
            if ($Clone) {
                if ($Query -ne 'Settings') { Write-Error "Clone flag only allowed for query type 'Setings.'`n"; return $null }
                switch ($For) {
                    'EndpointGroup' {  
                        $Pull = Get-Action1 EndpointGroups | Where-Object { $_.id -eq ($Clone) }
                        if (!$Pull) {
                            Write-Error "No $For found matching id $clone.`n"; return $null
                        }
                        else {
                            $sbAddIncludeFilter = { param( [string]$field_name, [string]$field_value) $this.include_filter += New-Object psobject -Property @{field_name = $field_name; field_value = $field_value; mode = 'include' } }
                            $sbDeleteIncludeFilter = { param([string]$field_name) $this.include_filter = @($this.include_filter | Where-Object { !($_.field_name -eq $field_name) }) }
                            $sbClearIncludeFilter = { $this.include_filter = @() }
                            $sbAddExcludeFilter = { param( [string]$field_name, [string]$field_value) $this.exclude_filter += New-Object psobject -Property @{field_name = $field_name; field_value = $field_value; mode = 'include' } }
                            $sbDeleteExcludeFilter = { param([string]$field_name) $this.exclude_filter = @($this.exclude_filter | Where-Object { !($_.field_name -eq $field_name) }) }
                            $sbClearExcludeFilter = { $this.exclude_filter = @() }
                            @('id', 'type', 'self', 'contents', 'uptime_alerts') | ForEach-Object { $Pull.PSObject.Members.Remove($_) }
                            $Pull | Add-Member -MemberType ScriptMethod -Name "AddIncludeFilter" -Value $sbAddIncludeFilter
                            $Pull | Add-Member -MemberType ScriptMethod -Name "DeleteIncludeFilter" -Value $sbDeleteIncludeFilter
                            $Pull | Add-Member -MemberType ScriptMethod -Name "ClearIncludeFilter" -Value $sbClearIncludeFilter
                            $Pull | Add-Member -MemberType ScriptMethod -Name "AddExcludeFilter" -Value $sbAddExcludeFilter
                            $Pull | Add-Member -MemberType ScriptMethod -Name "DeleteExcludeFilter" -Value $sbDeleteExcludeFilter
                            $Pull | Add-Member -MemberType ScriptMethod -Name "ClearExcludeFilter" -Value $sbClearExcludeFilter
                            return $Pull
                        }
                    }
                    'Automation' {
                        $Pull = Get-Action1 Automations | Where-Object { $_.id -eq ($Clone) }
                        if (!$Pull) {
                            Write-Error "No $For found matching id $clone."
                            return $null
                        }
                        else {
                            $sbAddEndpoint = { param([string]$Id) $this.endpoints += New-Object psobject -Property @{id = $Id; type = 'Endpoint' } }
                            $sbAddEndpointGroup = { param([string]$Id) $this.endpoints += New-Object psobject -Property @{id = $Id; type = 'EndpointGroup' } }
                            $sbDeleteEndpoint = { param([string]$Id) $this.endpoints = @($this.endpoints | Where-Object { !($_.type -eq 'Endpoint' -and $_.id -eq $Id) }) }
                            $sbDeleteEndpointGroup = { param([string]$Id) $this.endpoints = @($this.endpoints | Where-Object { !($_.type -eq 'EndpointGroup' -and $_.id -eq $Id) }) }
                            $sbClearEndpoints = { $this.endpoints = @() }
                            $sbDeferExecution = { $this.settings = 'DISABLED' }
                        
                            @('id', 'type', 'self', 'last_run', 'next_run', 'system', 'randomize_start') | ForEach-Object { $Pull.PSObject.Members.Remove($_) }
                            $CleanEndpoints = @()
                            $Pull.endpoints | ForEach-Object { $CleanEndpoints += New-Object psobject -Property @{id = $_.id; type = $_.type } }
                            $Pull.endpoints = $CleanEndpoints
                            $Pull | Add-Member -MemberType ScriptMethod -Name "AddEndpoint" -Value $sbAddEndpoint
                            $Pull | Add-Member -MemberType ScriptMethod -Name "AddEndpointGroup" -Value $sbAddEndpointGroup
                            $Pull | Add-Member -MemberType ScriptMethod -Name "DeleteEndpoint" -Value $sbDeleteEndpoint
                            $Pull | Add-Member -MemberType ScriptMethod -Name "DeleteEndpointGroup" -Value $sbDeleteEndpointGroup
                            $Pull | Add-Member -MemberType ScriptMethod -Name "ClearEndpoints" -Value $sbClearEndpoints
                            $Pull | Add-Member -MemberType ScriptMethod -Name "DeferExecution" -Value $sbDeferExecution
                            return $Pull
                        }
                    }
                    default { Write-Error "Invalild request to clone type $For." ; return $null }
                }
            }
            else {
                switch ($For) {
                    #Case out specific mods for any one base type.
                    'EndpointGroup' {
                        $sbAddIncludeFilter = { param( [string]$field_name, [string]$field_value) $this.include_filter += New-Object psobject -Property @{field_name = $field_name; field_value = $field_value; mode = 'include' } }
                        $sbDeleteIncludeFilter = { param([string]$field_name) $this.include_filter = @($this.include_filter | Where-Object { !($_.field_name -eq $field_name) }) }
                        $sbSetIncludeLogic = { param([string]$value) $this.include_filter_logic = $value }
                        $sbClearIncludeFilter = { $this.include_filter = @() }
                        $sbAddExcludeFilter = { param([string]$field_name, [string]$field_value) $this.exclude_filter += New-Object psobject -Property @{field_name = $field_name; field_value = $field_value; mode = 'include' } }
                        $sbDeleteExcludeFilter = { param([string]$field_name) $this.exclude_filter = @($this.exclude_filter | Where-Object { !($_.field_name -eq $field_name) }) }
                        $sbSetExcludeLogic = { param([string]$value) $this.include_filter_logic = $value }
                        $sbClearExcludeFilter = { $this.exclude_filter = @() }

                        $ret = New-Object psobject -Property @{name = 'Default Group Name'; description = 'Default Description'; include_filter_logic = ''; include_filter = @() ; exclude_filter = @() }

                        $ret | Add-Member -MemberType ScriptMethod -Name "AddIncludeFilter" -Value $sbAddIncludeFilter
                        $ret | Add-Member -MemberType ScriptMethod -Name "DeleteIncludeFilter" -Value $sbDeleteIncludeFilter
                        $ret | Add-Member -MemberType ScriptMethod -Name "ClearIncludeFilter" -Value $sbClearIncludeFilter
                        $ret | Add-Member -MemberType ScriptMethod -Name "SetIncludeLogic" -Value $sbSetIncludeLogic
                        $ret | Add-Member -MemberType ScriptMethod -Name "AddExcludeFilter" -Value $sbAddExcludeFilter
                        $ret | Add-Member -MemberType ScriptMethod -Name "DeleteExcludeFilter" -Value $sbDeleteExcludeFilter
                        $ret | Add-Member -MemberType ScriptMethod -Name "ClearExcludeFilter" -Value $sbClearExcludeFilter
                        $ret | Add-Member -MemberType ScriptMethod -Name "SetExcludeLogic" -Value $sbSetExcludeLogic
                        return $ret
                    }
                    { $_ -in @('Remediation', 'DeferredRemediation') } { 
                        
                        $deploy = ConvertFrom-Json $RemediationTemplate
                        $deploy.name = "E$tempxternal $For template $((Get-Date).ToString('yyyyMMddhhmmss'))"
                        $deploy.actions[0].params.display_summary = "$For via external API call."
                        $sbRefreshCVEList = {
                            $Script:Action1_CVE_Lookup = @{}
                            Debug-Host "Refreshing CVE list at $(Get-Date)"
                            Get-Action1 Vulnerabilities | ForEach-Object{$Script:Action1_CVE_Lookup[$_.cve_id]=$_}
                        }
                        $sbAddCVE = {
                            param([string]$CVE_ID) 
                            $vul = (($Script:Action1_CVE_Lookup[$CVE_ID]).software).available_updates
                            if ($null -eq $vul) {
                                Write-Host "No patch for $CVE_ID found in Action1." -ForegroundColor Red
                            }
                            else { 
                                foreach ($item in $vul) {
                                    $upd = $item.package_id
                                    $ver = $item.version
                                    $name = $item.name
                                    if (!($null -eq $this.actions.params.packages[0].$upd)) {
                                        Debug-Host "$upd has already been added to this template.`nThis happens when an update addresses more than one CVE in a single package."
                                    }
                                    else {
                                        Debug-Host "Adding $upd to the package list for $CVE_ID."
                                        if ($null -eq $this.actions.params.packages[0].'default') {
                                            $this.actions.params.packages += New-Object PSCustomObject -Property @{$upd = $ver }
                                        }
                                        else {
                                            $this.actions.params.packages[0] = New-Object PSCustomObject -Property @{$upd = $ver }
                                        }
                                    }
                                }
                            }
                        }
                        $sbAddEndpointGroup = { param([string]$Id) if ($this.endpoints[0].id -eq 'All') { $this.endpoints[0] = New-Object psobject -Property @{id = $Id; type = 'EndpointGroup' } }else { $this.endpoints += New-Object psobject -Property @{id = $Id; type = 'EndpointGroup' } } }
                        
                        $deploy | Add-Member -MemberType ScriptMethod -Name "AddCVE" -Value $sbAddCVE
                        $deploy | Add-Member -MemberType ScriptMethod -Name "AddEndpointGroup" -Value $sbAddEndpointGroup
                        $deploy | Add-Member -MemberType ScriptMethod -Name "RefreshCVEList" -Value $sbRefreshCVEList
                        if ($_ -eq 'Deferredremediation') { $deploy | Add-Member -MemberType NoteProperty -Name "settings" -Value 'DISABLED' }
                        #$deploy.settings = "ENABLED ONCE AT:$((Get-Date).ToUniversalTime().AddMinutes(10).ToString("HH-mm-ss")) DATE:$((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd"))"}
                        $deploy.RefreshCVEList()
                        return $deploy
                    }
                    'DeploySoftware' {
                        $deploy = ConvertFrom-Json $PackageDeployTemplate
                        $deploy.name = "External $For template $((Get-Date).ToString('yyyyMMddhhmmss'))"
                        $deploy.actions[0].params.display_summary = "$For via external API call."

                        $sbAddEndpoint = { param([string]$Id) if ('All' -eq $this.endpoints[0].id) { $this.ClearEndpoints() }; $this.endpoints += New-Object psobject -Property @{id = $Id; type = 'Endpoint' } }
                        $sbAddEndpointGroup = { param([string]$Id) if ('All' -eq $this.endpoints[0].id) { $this.ClearEndpoints() }; $this.endpoints += New-Object psobject -Property @{id = $Id; type = 'EndpointGroup' } }
                        $sbDeleteEndpoint = { param([string]$Id) $this.endpoints = @($this.endpoints | Where-Object { !($_.type -eq 'Endpoint' -and $_.id -eq $Id) }) }
                        $sbDeleteEndpointGroup = { param([string]$Id) $this.endpoints = @($this.endpoints | Where-Object { !($_.type -eq 'EndpointGroup' -and $_.id -eq $Id) }) }
                        $sbClearEndpoints = { $this.endpoints = @() }
                        $sbAddPackage = {
                            param([string]$Package_ID) 
                            $pack = Get-Action1 Packages | Where-Object { $_.id -eq $Package_ID }
                            $name = $pack.name
                            if ($null -eq $pack) {
                                Write-Host "Unable to locate package $Package_ID." -ForegroundColor Red
                            }
                            else { 
                                if (!($null -eq $this.actions.params.packages[0].$pack)) {
                                    Debug-Host "$name has already been added to this template."
                                }
                                else {
                                    $version = $(Get-Action1 RawURI -URI "$Script:Action1_BaseURI/packages/all/$Package_ID/versions").version
                                    Debug-Host "Adding $name version $Version to the package list."
                                    if ($null -eq $this.actions.params.packages[0].'default') {
                                        $this.actions.params.packages += New-Object PSCustomObject -Property @{$Package_ID = $version }
                                    }
                                    else {
                                        $this.actions.params.packages[0] = New-Object PSCustomObject -Property @{$Package_ID = $version }
                                    }
                                }
                            }
                        }
                        $deploy | Add-Member -MemberType ScriptMethod -Name "AddEndpoint" -Value $sbAddEndpoint
                        $deploy | Add-Member -MemberType ScriptMethod -Name "AddEndpointGroup" -Value $sbAddEndpointGroup
                        $deploy | Add-Member -MemberType ScriptMethod -Name "DeleteEndpoint" -Value $sbDeleteEndpoint
                        $deploy | Add-Member -MemberType ScriptMethod -Name "DeleteEndpointGroup" -Value $sbDeleteEndpointGroup
                        $deploy | Add-Member -MemberType ScriptMethod -Name "ClearEndpoints" -Value $sbClearEndpoints
                        $deploy | Add-Member -MemberType ScriptMethod -Name "AddPackage" -Value $sbAddPackage
                        return $deploy
                    }
                    default { Write-Error "Invalild request for template type $For." ; return $null }
                }
            }
        } 
    }
    # Note things that do not get procesed post API call, and should be delivered unaltered.
    $Rawlist = @('ReportExport', 'Logs')

    $AddArgs = ""
    $sbPolicyResultsDetail = {
        $Page = Invoke-Action1ApiRequest -Method GET -Path $this.details -Label 'PolicyResultsDetails'
        $Page.items | Write-Output
        While (![string]::IsNullOrEmpty($Page.next_page)) {
            $Page = Invoke-Action1ApiRequest -Method GET -Path $Page.next_page -Label 'PolicyResultsDetails'
            $Page.items | Write-Output
        }
    }
    $sbCustomFieldGet = { param([string]$name)($this.custom | Where-Object { $_.name -eq $name }).value }

    if ($null -eq $Limit){$Limit=200}
    if ($Limit -gt 0) { 
        $AddArgs = Join-QueryString -QueryString $AddArgs -Argument "limit=$Limit"
    }
    else {
        $AddArgs = Join-QueryString -QueryString $AddArgs -Argument "limit=200"
    }
    if (!$URILookUp["G_$Query"].ToString().Contains("`$Org_ID")) {
        if (!$URILookUp["G_$Query"].ToString().Contains("`$Object_ID")) {
            $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["G_$Query"])
        }
        else {
            if ($Id) {
                $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["G_$Query"] -Object_ID $Id)
            }
            else {
                Write-Error 'This options requires that you specify an Object_ID.'
            }
        }
    }
    else {
        if ($Id) {
            $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["G_$Query"] -Org_ID $(Initialize-Action1DefaultOrg) -Object_ID $Id)
        }
        else {
            $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["G_$Query"] -Org_ID $(Initialize-Action1DefaultOrg))
        }
    } 
    if ($Rawlist.Contains($Query)) {
         $Page = Invoke-Action1ApiRequest -Method GET -Path $Path -Label $Query -AddArgs $AddArgs -RawResponse 
    } 
    else {
         $Page = Invoke-Action1ApiRequest -Method GET -Path $Path -Label $Query -AddArgs $AddArgs 
    }
    if ($Page.items) {
        switch -Wildcard ($Query) {
            'PolicyResults' {
                $page.Items | ForEach-Object {
                    $_ | Add-Member -MemberType ScriptMethod -Name "GetDetails" -Value $sbPolicyResultsDetail
                    Write-Output $_
                }
            }
            'Endpoint*' {
                $page.Items | ForEach-Object {
                    $_ | Add-Member -MemberType ScriptMethod -Name "GetCustomAttribute" -Value $sbCustomFieldGet
                    Write-Output $_
                }  
            }
            default { $Page.Items | Write-Output }
        }
        While (![string]::IsNullOrEmpty($Page.next_page)) {
            Debug-Host "[$Query] Next page..."
            if ($Rawlist.Contains($Query)) {
                 $Page = Invoke-Action1ApiRequest -Method GET -Path $Page.next_page -Label $Query -RawResponse 
            } 
            else {
                 $Page = Invoke-Action1ApiRequest -Method GET -Path $Page.next_page -Label $Query 
            }
            switch -Wildcard ($Query) {
                'PolicyResults' {
                    $page.Items | ForEach-Object {
                        $_ | Add-Member -MemberType ScriptMethod -Name "GetDetails" -Value sbPolicyResultsDetail
                        Write-Output $_
                    }
                }
                'Endpoint*' {
                    $page.Items | ForEach-Object {
                        $_ | Add-Member -MemberType ScriptMethod -Name "GetCustomAttribute" -Value $sbCustomFieldGet
                        Write-Output $_
                    }  
                }
                default { $Page.Items | Write-Output }
            }
        }
    }
    else {
        switch -Wildcard ($Query) {
            'Endpoint*' {
                $Page | Add-Member -MemberType ScriptMethod -Name "GetCustomAttribute" -Value $sbCustomFieldGet
                Write-Output $Page
                
            }
            default { Write-Output $Page }
        }
    }                
    
}

function New-Action1 {
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'EndpointGroup',
            'Organization',
            'Automation',
            'Remediation',
            'DeferredRemediation',
            'DeploySoftware',
            'RawURI'
        )]
        [string]$Item,
        [string]$URI,
        [Parameter(Mandatory)]
        [object]$Data                    
    )
        Debug-Host "Creating new $Item."
    #Short out processing path if URI literal is specified.
    if ($Item -eq 'RawURI') {
         if (!$URI) {
             Write-Error "Error -URI value required when Action is type RawURI.`n"; 
             return $null 
        }
        else { 
            return Invoke-Action1ApiRequest -Method POST -Path $URI -Body $Data -Label 'RawRequest'
        } 
    }
    try {
        if (!$URILookUp["N_$Item"].ToString().Contains("`$Org_ID")) {
            $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["N_$Item"])
        }
        else {
            $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["N_$Item"] -Org_ID $(Initialize-Action1DefaultOrg))
        } 
        return Invoke-Action1ApiRequest -Method POST -Path $Path -Label $Item -Body $Data
    }
    catch {
        Write-Error "Error adding $Item`: $($_)."
        return $null
    }
    
}

function Update-Action1 {
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'Modify',
            'ModifyMembers', 
            'Delete'
        )]
        [String]$Action,
        [Parameter(Mandatory)]
        [ValidateSet(
            'EndpointGroup',
            'Endpoint',
            'Automation',
            'CustomAttribute',
            'RawURI'
        )]
        [string]$Type,
        [object]$Data,
        [string]$Id,
        [string]$AttributeName,
        [string]$AttributeValue,
        [string]$URI,
        [switch]$Force
    )
    Debug-Host "Trying update for $Action => $Type."
    #Short out processing path if URI literal is specified.
    if ($Type -eq 'RawURI') {
        if (!$URI) {
             Write-Error "Error -URI value required when Action is type RawURI.`n"; 
             return $null 
        }
        else {
            return Invoke-Action1ApiRequest -Method PATCH -Path $URI -Body $Data -Label 'RawRequest' 
        } 
    }
    switch ($Action) {
        'ModifyMembers' {
            switch ($Type) {
                'EndpointGroup' { 
                    $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["U_GroupMembers"] -Org_ID $(Initialize-Action1DefaultOrg) -Object_ID $id)
                    return Invoke-Action1ApiRequest -Method POST -Path $Path -Body $Data -Label "$Action=>$Type"
                }
                default { Write-Error "Invalid request of $Type for query $Action." ; return $null }
            }
        }
        'Modify' {              
            if (!$Id) { Write-Error "When perfoming $Action=>$Type, the value for -Id must be specified to know what object to act on."; return $null } 
            switch ($Type) {
                'Automation' {
                    $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["U_Automation"] -Org_ID $(Initialize-Action1DefaultOrg) -Object_Id $Id)
                    return Invoke-Action1ApiRequest -Method PATCH -Path $Path -Body $Data -Label "$Action=>$Type" 
                }
                'CustomAttribute' {
                    $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["U_Endpoint"] -Org_ID $(Initialize-Action1DefaultOrg) -Object_Id $Id)
                    $Data = New-Object psobject -Property @{"custom:$AttributeName" = $AttributeValue }
                    return Invoke-Action1ApiRequest -Method PATCH -Path $Path -Body $Data -Label "$Action=>$Type" 
                }
                'Endpoint' { 
                    $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["U_Endpoint"] -Org_ID $(Initialize-Action1DefaultOrg) -Object_Id $Id)
                    $Data.PSObject.Members | ForEach-Object { if (@('name', 'comment') -notcontains $_.Name) { $Data.PSObject.Members.Remove($_.Name) } }
                    return Invoke-Action1ApiRequest -Method PATCH -Path $Path -Body $Data -Label "$Action=>$Type" 
                }
                'EndpointGroup' { 
                    $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["U_GroupModify"] -Org_ID $(Initialize-Action1DefaultOrg) -Object_Id $Id)
                    return Invoke-Action1ApiRequest -Method PATCH -Path $Path -Body $Data -Label "$Action=>$Type"
                }
                default { Write-Error "Invalid request of $Type for query $Action." ; return $null }
            }   
        }
        'Delete' {
            Debug-Host "Force delete enabled:$Force."
            switch ($Type) {
                'EndpointGroup' { 
                    if ($force -or ((Read-Host "Are you sure you want to $Action $Type [$id]?`n[Y]es to confirm, any other key to cancel.") -eq 'Y')) {
                        $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["U_GroupModify"] -Org_ID $(Initialize-Action1DefaultOrg) -Object_Id $Id)
                        return Invoke-Action1ApiRequest -Method DELETE -Path $Path -Label "$Action=>$Type"
                    }
                }
                'Endpoint' { 
                    if ($force -or ((Read-Host "Are you sure you want to $Action $Type [$id]?`n[Y]es to confirm, any other key to cancel.") -eq 'Y')) {
                        $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["U_Endpoint"] -Org_ID $(Initialize-Action1DefaultOrg) -Object_Id $Id)
                        return Invoke-Action1ApiRequest -Method DELETE -Path $Path -Label "$Action=>$Type"
                    }
                }
                'Automation' {
                    if ($force -or ((Read-Host "Are you sure you want to $Action $Type [$id]?`n[Y]es to confirm, any other key to cancel.") -eq 'Y')) {
                        $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["U_Automation"] -Org_ID $(Initialize-Action1DefaultOrg) -Object_Id $Id)
                        return Invoke-Action1ApiRequest -Method DELETE -Path $Path -Label "$Action=>$Type"
                    }
                }
                default { Write-Error "Invalid request of $Type for query $Action." ; return $null }
            }
        }
        default { Write-Error "Invalid request of $Type for query $Action." ; return $null }
    }
}

function Start-Action1Requery {
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'ReportData',
            'InstalledSoftware',
            'InstalledUpdates'
        )]
        [string]$Type,
        [string]$Endpoint_Id                    
    )
    if (!$URILookUp["R_$Type"].ToString().Contains("`$Org_ID")) {
        $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["R_$Type"])
    }
    else {
        if ($Endpoint_Id) {
            if ($URILookUp["R_$Type"].ToString().Contains("`$Object_ID")) {
                $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["R_$Type"] -Org_ID $(Initialize-Action1DefaultOrg) -Object_ID $Endpoint_Id)
            }
            else {
                Write-Error "Endpoint_Id was specified but this action is not endpoint specific, can continue, defaulting to system wide."
                $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["R_$Type"] -Org_ID $(Initialize-Action1DefaultOrg))
            } 
        }
        else {
            $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["R_$Type"] -Org_ID $(Initialize-Action1DefaultOrg))
        }
    } 

    return Invoke-Action1ApiRequest -Method POST -Path $Path.TrimEnd('/') -Label "Requery=>$Type"  
}

