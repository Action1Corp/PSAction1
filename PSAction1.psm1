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


# SIG # Begin signature block
# MII9NAYJKoZIhvcNAQcCoII9JTCCPSECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBcp71K7G+AJQJP
# KQyIKAsnqjIPL0PJyK9KaaQmIEYbM6CCIfYwggXMMIIDtKADAgECAhBUmNLR1FsZ
# lUgTecgRwIeZMA0GCSqGSIb3DQEBDAUAMHcxCzAJBgNVBAYTAlVTMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xSDBGBgNVBAMTP01pY3Jvc29mdCBJZGVu
# dGl0eSBWZXJpZmljYXRpb24gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAy
# MDAeFw0yMDA0MTYxODM2MTZaFw00NTA0MTYxODQ0NDBaMHcxCzAJBgNVBAYTAlVT
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xSDBGBgNVBAMTP01pY3Jv
# c29mdCBJZGVudGl0eSBWZXJpZmljYXRpb24gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRo
# b3JpdHkgMjAyMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALORKgeD
# Bmf9np3gx8C3pOZCBH8Ppttf+9Va10Wg+3cL8IDzpm1aTXlT2KCGhFdFIMeiVPvH
# or+Kx24186IVxC9O40qFlkkN/76Z2BT2vCcH7kKbK/ULkgbk/WkTZaiRcvKYhOuD
# PQ7k13ESSCHLDe32R0m3m/nJxxe2hE//uKya13NnSYXjhr03QNAlhtTetcJtYmrV
# qXi8LW9J+eVsFBT9FMfTZRY33stuvF4pjf1imxUs1gXmuYkyM6Nix9fWUmcIxC70
# ViueC4fM7Ke0pqrrBc0ZV6U6CwQnHJFnni1iLS8evtrAIMsEGcoz+4m+mOJyoHI1
# vnnhnINv5G0Xb5DzPQCGdTiO0OBJmrvb0/gwytVXiGhNctO/bX9x2P29Da6SZEi3
# W295JrXNm5UhhNHvDzI9e1eM80UHTHzgXhgONXaLbZ7LNnSrBfjgc10yVpRnlyUK
# xjU9lJfnwUSLgP3B+PR0GeUw9gb7IVc+BhyLaxWGJ0l7gpPKWeh1R+g/OPTHU3mg
# trTiXFHvvV84wRPmeAyVWi7FQFkozA8kwOy6CXcjmTimthzax7ogttc32H83rwjj
# O3HbbnMbfZlysOSGM1l0tRYAe1BtxoYT2v3EOYI9JACaYNq6lMAFUSw0rFCZE4e7
# swWAsk0wAly4JoNdtGNz764jlU9gKL431VulAgMBAAGjVDBSMA4GA1UdDwEB/wQE
# AwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTIftJqhSobyhmYBAcnz1AQ
# T2ioojAQBgkrBgEEAYI3FQEEAwIBADANBgkqhkiG9w0BAQwFAAOCAgEAr2rd5hnn
# LZRDGU7L6VCVZKUDkQKL4jaAOxWiUsIWGbZqWl10QzD0m/9gdAmxIR6QFm3FJI9c
# Zohj9E/MffISTEAQiwGf2qnIrvKVG8+dBetJPnSgaFvlVixlHIJ+U9pW2UYXeZJF
# xBA2CFIpF8svpvJ+1Gkkih6PsHMNzBxKq7Kq7aeRYwFkIqgyuH4yKLNncy2RtNwx
# AQv3Rwqm8ddK7VZgxCwIo3tAsLx0J1KH1r6I3TeKiW5niB31yV2g/rarOoDXGpc8
# FzYiQR6sTdWD5jw4vU8w6VSp07YEwzJ2YbuwGMUrGLPAgNW3lbBeUU0i/OxYqujY
# lLSlLu2S3ucYfCFX3VVj979tzR/SpncocMfiWzpbCNJbTsgAlrPhgzavhgplXHT2
# 6ux6anSg8Evu75SjrFDyh+3XOjCDyft9V77l4/hByuVkrrOj7FjshZrM77nq81YY
# uVxzmq/FdxeDWds3GhhyVKVB0rYjdaNDmuV3fJZ5t0GNv+zcgKCf0Xd1WF81E+Al
# GmcLfc4l+gcK5GEh2NQc5QfGNpn0ltDGFf5Ozdeui53bFv0ExpK91IjmqaOqu/dk
# ODtfzAzQNb50GQOmxapMomE2gj4d8yu8l13bS3g7LfU772Aj6PXsCyM2la+YZr9T
# 03u4aUoqlmZpxJTG9F9urJh4iIAGXKKy7aIwggaoMIIEkKADAgECAhMzAAFBLsM2
# hq9VZ1bpAAAAAUEuMA0GCSqGSIb3DQEBDAUAMFoxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDUyBFT0MgQ0EgMDMwHhcNMjYwNTIxMTQxNjAyWhcNMjYwNTI0
# MTQxNjAyWjBrMQswCQYDVQQGEwJVUzEOMAwGA1UECBMFVGV4YXMxEDAOBgNVBAcT
# B0hvdXN0b24xHDAaBgNVBAoTE0FjdGlvbjEgQ29ycG9yYXRpb24xHDAaBgNVBAMT
# E0FjdGlvbjEgQ29ycG9yYXRpb24wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQCvZcTdtPDwx/lAE5WUaS/57cIw/dmMvk25IJ6rBQxggMK21gihEZcN0kmd
# SrplzExy4ps/8+nxtxPsmO+gaz41Etm7k5/og3xRBQ40M34eTdG8EGQDz9bOkLTU
# ZdkCHFLnqA8AL91gltZjq6WOdT/rsg6XeLva6TkhCSvgWMLWkjK8Dt2qYlqfRYhH
# AF4U9KbaVpfCG4pvAbDPC8GtWkQEC3w5fiNM+eJBEn0jh+/MNGzqPKwvj0RGYNuJ
# ML/CFsZCBMj3TmVEQ83KmW5P4GRKkQevyxIcmxSHeQQwweX7XE2Ae9M5UQdQECFe
# XkNzYDfGcQsPffrxt2kfPuaQOvcOZveJ1hteZAIp1BEa1WuERWIZVP9tiYpP98v3
# mf/kw4K84pq8+S+lfF37WOyC4BqH1m6nCxZXasAD6WRirElHYcTcow+14MVQVMYs
# q1NboAXFlE6UvG3PVO2rxz37/dTlPC4FKUnFzACNw4c4m65xag59Vsf/jaU5WLwx
# WW1V3QcCAwEAAaOCAdQwggHQMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeA
# MDsGA1UdJQQ0MDIGCisGAQQBgjdhAQAGCCsGAQUFBwMDBhorBgEEAYI3YYTGyjWC
# 84fIeoPTzfIboMPaLTAdBgNVHQ4EFgQUk/vFDrNjPPdtOBJQB09OzhnwJ24wHwYD
# VR0jBBgwFoAUa16lNMMFxWJKIVqOq3NgYtSsY4UwZwYDVR0fBGAwXjBcoFqgWIZW
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# SUQlMjBWZXJpZmllZCUyMENTJTIwRU9DJTIwQ0ElMjAwMy5jcmwwdAYIKwYBBQUH
# AQEEaDBmMGQGCCsGAQUFBzAChlhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUyMEVPQyUy
# MENBJTIwMDMuY3J0MFQGA1UdIARNMEswSQYEVR0gADBBMD8GCCsGAQUFBwIBFjNo
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5o
# dG0wDQYJKoZIhvcNAQEMBQADggIBACi8kN3goukTowT2yx7kxCKG9XehSulFN9+1
# yv0p+q2l4JOKO2SgTJ53SEN1JP7pimRK07GA/UapjlvYjRg4pJ3t+sBPa/BMcCn3
# bSC7iLPrJqRdi41xDT8Q9TS/dKlGc1IU0RKyfqBPFEi5UjZKPhdhPsVRTHVRbVJw
# oL8cmdV6bVZ/rG0zr1e4ARSSBpr9fep0H9zpXcWQgQVWHkR8NknBkX0LeATXqGKi
# 7GSx+z6fVesIgkIh6NaDa8KwHwSstwskhp+VeWo0+M677SSLgLJ4f1KtYoIK2HUY
# i+FWwzx8caWUjOIt92ufMXZksNdLb+RtRiuMsM4dwJ+iiKtHwKjoVXgS9tDxLrjU
# wZuFtRgOQXYKv2DZBL4wMR3vXARJNuXAet3BpUJSMOv4RxI4hmBw1RmoH8Xi4d9Z
# aLR7Fw85OXNpP0Xvr5badr+Wd98tk3V+Cwq6r4mfD1080aWmD4RapXbD78ewazxu
# LYRpP1OAAnUQySNGF8YdzUurBoVp+fFv54C5BKxTuuehu390QDSu/1ATx0H95qgZ
# 7CE9g4z3ZT9MHNEkrRijJCD9xlTheoi76GmKdYdEjIZSz2j48nEEjgBltSzjaQB9
# e+0X4FWxH20XcUtYQzhhX1itgrWWTT3DdvDvzUxrVpfuX3Fb9aD/UT4rdlIgX8O6
# 9RUtKYULMIIGqDCCBJCgAwIBAgITMwABQS7DNoavVWdW6QAAAAFBLjANBgkqhkiG
# 9w0BAQwFADBaMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgSUQgVmVyaWZpZWQgQ1MgRU9DIENB
# IDAzMB4XDTI2MDUyMTE0MTYwMloXDTI2MDUyNDE0MTYwMlowazELMAkGA1UEBhMC
# VVMxDjAMBgNVBAgTBVRleGFzMRAwDgYDVQQHEwdIb3VzdG9uMRwwGgYDVQQKExNB
# Y3Rpb24xIENvcnBvcmF0aW9uMRwwGgYDVQQDExNBY3Rpb24xIENvcnBvcmF0aW9u
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAr2XE3bTw8Mf5QBOVlGkv
# +e3CMP3ZjL5NuSCeqwUMYIDCttYIoRGXDdJJnUq6ZcxMcuKbP/Pp8bcT7JjvoGs+
# NRLZu5Of6IN8UQUONDN+Hk3RvBBkA8/WzpC01GXZAhxS56gPAC/dYJbWY6uljnU/
# 67IOl3i72uk5IQkr4FjC1pIyvA7dqmJan0WIRwBeFPSm2laXwhuKbwGwzwvBrVpE
# BAt8OX4jTPniQRJ9I4fvzDRs6jysL49ERmDbiTC/whbGQgTI905lREPNypluT+Bk
# SpEHr8sSHJsUh3kEMMHl+1xNgHvTOVEHUBAhXl5Dc2A3xnELD3368bdpHz7mkDr3
# Dmb3idYbXmQCKdQRGtVrhEViGVT/bYmKT/fL95n/5MOCvOKavPkvpXxd+1jsguAa
# h9ZupwsWV2rAA+lkYqxJR2HE3KMPteDFUFTGLKtTW6AFxZROlLxtz1Ttq8c9+/3U
# 5TwuBSlJxcwAjcOHOJuucWoOfVbH/42lOVi8MVltVd0HAgMBAAGjggHUMIIB0DAM
# BgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDA7BgNVHSUENDAyBgorBgEEAYI3
# YQEABggrBgEFBQcDAwYaKwYBBAGCN2GExso1gvOHyHqD083yG6DD2i0wHQYDVR0O
# BBYEFJP7xQ6zYzz3bTgSUAdPTs4Z8CduMB8GA1UdIwQYMBaAFGtepTTDBcViSiFa
# jqtzYGLUrGOFMGcGA1UdHwRgMF4wXKBaoFiGVmh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUy
# MEVPQyUyMENBJTIwMDMuY3JsMHQGCCsGAQUFBwEBBGgwZjBkBggrBgEFBQcwAoZY
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQl
# MjBJRCUyMFZlcmlmaWVkJTIwQ1MlMjBFT0MlMjBDQSUyMDAzLmNydDBUBgNVHSAE
# TTBLMEkGBFUdIAAwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMA0GCSqGSIb3DQEBDAUAA4IC
# AQAovJDd4KLpE6ME9sse5MQihvV3oUrpRTfftcr9KfqtpeCTijtkoEyed0hDdST+
# 6YpkStOxgP1GqY5b2I0YOKSd7frAT2vwTHAp920gu4iz6yakXYuNcQ0/EPU0v3Sp
# RnNSFNESsn6gTxRIuVI2Sj4XYT7FUUx1UW1ScKC/HJnVem1Wf6xtM69XuAEUkgaa
# /X3qdB/c6V3FkIEFVh5EfDZJwZF9C3gE16hiouxksfs+n1XrCIJCIejWg2vCsB8E
# rLcLJIaflXlqNPjOu+0ki4CyeH9SrWKCCth1GIvhVsM8fHGllIziLfdrnzF2ZLDX
# S2/kbUYrjLDOHcCfooirR8Co6FV4EvbQ8S641MGbhbUYDkF2Cr9g2QS+MDEd71wE
# STblwHrdwaVCUjDr+EcSOIZgcNUZqB/F4uHfWWi0excPOTlzaT9F76+W2na/lnff
# LZN1fgsKuq+Jnw9dPNGlpg+EWqV2w+/HsGs8bi2EaT9TgAJ1EMkjRhfGHc1LqwaF
# afnxb+eAuQSsU7rnobt/dEA0rv9QE8dB/eaoGewhPYOM92U/TBzRJK0YoyQg/cZU
# 4XqIu+hpinWHRIyGUs9o+PJxBI4AZbUs42kAfXvtF+BVsR9tF3FLWEM4YV9YrYK1
# lk09w3bw781Ma1aX7l9xW/Wg/1E+K3ZSIF/DuvUVLSmFCzCCBygwggUQoAMCAQIC
# EzMAAAAVBT5uGY6TKdkAAAAAABUwDQYJKoZIhvcNAQEMBQAwYzELMAkGA1UEBhMC
# VVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE0MDIGA1UEAxMrTWlj
# cm9zb2Z0IElEIFZlcmlmaWVkIENvZGUgU2lnbmluZyBQQ0EgMjAyMTAeFw0yNjAz
# MjYxODExMjhaFw0zMTAzMjYxODExMjhaMFoxCzAJBgNVBAYTAlVTMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJRCBW
# ZXJpZmllZCBDUyBFT0MgQ0EgMDMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQDg9Ms9AqovDnMePvMOe+KybhCd8+lokzYORlS3kBVXseecbyGwBcsenlm5
# bLtMGPjiIFLzBQF+ghlVV/U29q5GcdeEEBCHTTGhL2koIrLc4UrliMRcbv9mOMtR
# /l7/xAmv0Fx4BJHn1dHt37fvrBqXmKjKfGf5DpyO/+hnV7TEreMtS19iO+bjZ/9H
# npg3PCk0e7YSbRTFkx97FZwRWpC4s3NepRfRXQh/WMAj7JmsYeVZohi4TF5yW2JM
# rJZqwHcyzJZYtD2Hlno5ZEJkdiZcEaxHOobmwO06Z1J9c23ps9PGIhGaq1sKLEAz
# 9Doc5rLkYWGteDrscKhAp2kIc/oYlH9Ij6BkOqqgWINEkEtC8ZNG1Mak+h3o65aj
# 0iQKmdxW7IZaHO5cuyoMi+KtYfXeIIg3sVIbS2EL8kUtsDGdEqNqAq/isqTi1jXq
# Le6iKp1ni1SPdvPW9G03CTsYF68b/yuIQRwbdoBCXemMNJCS0dorCRY4b2WAAy4n
# g7SANcEgrBgZf535+QfLU5hGzrKjIpbMabauWb5FKWUKkMsPcXFkXRWO4noKPm4K
# WlFypqOpbJ/KONVReIlxHQRegAOBzIhRB7gr9IDQ1sc2MgOgQ+xVGW4oq4HD0mfA
# iwiyLskZrkaQ7JoanYjBNcR9RS26YxAVbcBtLitFTzCIEg5ZdQIDAQABo4IB3DCC
# AdgwDgYDVR0PAQH/BAQDAgGGMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRr
# XqU0wwXFYkohWo6rc2Bi1KxjhTBUBgNVHSAETTBLMEkGBFUdIAAwQTA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9z
# aXRvcnkuaHRtMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMBIGA1UdEwEB/wQI
# MAYBAf8CAQAwHwYDVR0jBBgwFoAU2UEpsA8PY2zvadf1zSmepEhqMOYwcAYDVR0f
# BGkwZzBloGOgYYZfaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwv
# TWljcm9zb2Z0JTIwSUQlMjBWZXJpZmllZCUyMENvZGUlMjBTaWduaW5nJTIwUENB
# JTIwMjAyMS5jcmwwfQYIKwYBBQUHAQEEcTBvMG0GCCsGAQUFBzAChmFodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIw
# VmVyaWZpZWQlMjBDb2RlJTIwU2lnbmluZyUyMFBDQSUyMDIwMjEuY3J0MA0GCSqG
# SIb3DQEBDAUAA4ICAQBdbiI8zwXLX8glJEh/8Q22UMCUhWBO46Z9FPhwOR3mdlqR
# VLkYOon/MczUwrjDhx3X99SPH5PSflkGoTvnO9ZWHM5YFVYpO7NYuB+mfVSGAGZw
# iGOASWk0i2B7vn9nElJJmoiXxugfH5YdBsrUgTt0AFNXkzmqTgk+S1Hxb1u/0HCq
# EHVZPk2A/6eJXYbtpRM5Fcz00jisUl9BRZgSebODV85bBzOveqyC3f0PnHCxRJNh
# Mb8xP/sB/VI7pf2rheSV7zqUSv8vn/fIMblXeaVIlpqoq8SP9BJMjE/CoVXJxnkZ
# QRM1Fa7kN9yztvReOhxSgPgpZx/Xl/jkwyEFVJTBfBp3sTgfIc/pmqv2ehtakL2A
# Ej78EmOPQohxJT3wyX+P78GA25tLpAvzj3RMMHd8z18ZuuVi+60MAzGpOASH1L8N
# lr3fZRZnQO+pyye2DCvYmHaIfdUgYJqn7noxxGVv89+RaETh1tgCDvwNpFCSG7vl
# 5A4ako+2fx409r9TWjXC7Oif1IQ5ZJzB4Rf8GvBiHYjvMmHpledp1FGRLdSRFVpC
# 3/OKpZY6avIqZp7+8pP/WQP903DdgrvAT6W4xPOBxXPa4tGksN3SuqJaiFYHSNye
# Bufn8iseujW4IbBSbHD4BPqbF3qZ+7nG9d/d/G2/Lx4kH9cCmBfmsZdSkHmukDCC
# B54wggWGoAMCAQICEzMAAAAHh6M0o3uljhwAAAAAAAcwDQYJKoZIhvcNAQEMBQAw
# dzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjFI
# MEYGA1UEAxM/TWljcm9zb2Z0IElkZW50aXR5IFZlcmlmaWNhdGlvbiBSb290IENl
# cnRpZmljYXRlIEF1dGhvcml0eSAyMDIwMB4XDTIxMDQwMTIwMDUyMFoXDTM2MDQw
# MTIwMTUyMFowYzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjE0MDIGA1UEAxMrTWljcm9zb2Z0IElEIFZlcmlmaWVkIENvZGUgU2ln
# bmluZyBQQ0EgMjAyMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALLw
# wK8ZiCji3VR6TElsaQhVCbRS/3pK+MHrJSj3Zxd3KU3rlfL3qrZilYKJNqztA9OQ
# acr1AwoNcHbKBLbsQAhBnIB34zxf52bDpIO3NJlfIaTE/xrweLoQ71lzCHkD7A4A
# s1Bs076Iu+mA6cQzsYYH/Cbl1icwQ6C65rU4V9NQhNUwgrx9rGQ//h890Q8JdjLL
# w0nV+ayQ2Fbkd242o9kH82RZsH3HEyqjAB5a8+Ae2nPIPc8sZU6ZE7iRrRZywRmr
# KDp5+TcmJX9MRff241UaOBs4NmHOyke8oU1TYrkxh+YeHgfWo5tTgkoSMoayqoDp
# HOLJs+qG8Tvh8SnifW2Jj3+ii11TS8/FGngEaNAWrbyfNrC69oKpRQXY9bGH6jn9
# NEJv9weFxhTwyvx9OJLXmRGbAUXN1U9nf4lXezky6Uh/cgjkVd6CGUAf0K+Jw+GE
# /5VpIVbcNr9rNE50Sbmy/4RTCEGvOq3GhjITbCa4crCzTTHgYYjHs1NbOc6brH+e
# KpWLtr+bGecy9CrwQyx7S/BfYJ+ozst7+yZtG2wR461uckFu0t+gCwLdN0A6cFtS
# RtR8bvxVFyWwTtgMMFRuBa3vmUOTnfKLsLefRaQcVTgRnzeLzdpt32cdYKp+dhr2
# ogc+qM6K4CBI5/j4VFyC4QFeUP2YAidLtvpXRRo3AgMBAAGjggI1MIICMTAOBgNV
# HQ8BAf8EBAMCAYYwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNlBKbAPD2Ns
# 72nX9c0pnqRIajDmMFQGA1UdIARNMEswSQYEVR0gADBBMD8GCCsGAQUFBwIBFjNo
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5o
# dG0wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDwYDVR0TAQH/BAUwAwEB/zAf
# BgNVHSMEGDAWgBTIftJqhSobyhmYBAcnz1AQT2ioojCBhAYDVR0fBH0wezB5oHeg
# dYZzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0
# JTIwSWRlbnRpdHklMjBWZXJpZmljYXRpb24lMjBSb290JTIwQ2VydGlmaWNhdGUl
# MjBBdXRob3JpdHklMjAyMDIwLmNybDCBwwYIKwYBBQUHAQEEgbYwgbMwgYEGCCsG
# AQUFBzAChnVodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01p
# Y3Jvc29mdCUyMElkZW50aXR5JTIwVmVyaWZpY2F0aW9uJTIwUm9vdCUyMENlcnRp
# ZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAyMC5jcnQwLQYIKwYBBQUHMAGGIWh0dHA6
# Ly9vbmVvY3NwLm1pY3Jvc29mdC5jb20vb2NzcDANBgkqhkiG9w0BAQwFAAOCAgEA
# fyUqnv7Uq+rdZgrbVyNMul5skONbhls5fccPlmIbzi+OwVdPQ4H55v7VOInnmezQ
# EeW4LqK0wja+fBznANbXLB0KrdMCbHQpbLvG6UA/Xv2pfpVIE1CRFfNF4XKO8XYE
# a3oW8oVH+KZHgIQRIwAbyFKQ9iyj4aOWeAzwk+f9E5StNp5T8FG7/VEURIVWArbA
# zPt9ThVN3w1fAZkF7+YU9kbq1bCR2YD+MtunSQ1Rft6XG7b4e0ejRA7mB2IoX5hN
# h3UEauY0byxNRG+fT2MCEhQl9g2i2fs6VOG19CNep7SquKaBjhWmirYyANb0RJSL
# WjinMLXNOAga10n8i9jqeprzSMU5ODmrMCJE12xS/NWShg/tuLjAsKP6SzYZ+1Ry
# 358ZTFcx0FS/mx2vSoU8s8HRvy+rnXqyUJ9HBqS0DErVLjQwK8VtsBdekBmdTbQV
# oCgPCqr+PDPB3xajYnzevs7eidBsM71PINK2BoE2UfMwxCCX3mccFgx6UsQeRSdV
# VVNSyALQe6PT12418xon2iDGE81OGCreLzDcMAZnrUAx4XQLUz6ZTl65yPUiOh3k
# 7Yww94lDf+8oG2oZmDh5O1Qe38E+M3vhKwmzIeoB1dVLlz4i3IpaDcR+iuGjH2Td
# aC1ZOmBXiCRKJLj4DT2uhJ04ji+tHD6n58vhavFIrmcxghqUMIIakAIBATBxMFox
# CzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzAp
# BgNVBAMTIk1pY3Jvc29mdCBJRCBWZXJpZmllZCBDUyBFT0MgQ0EgMDMCEzMAAUEu
# wzaGr1VnVukAAAABQS4wDQYJYIZIAWUDBAIBBQCgXjAQBgorBgEEAYI3AgEMMQIw
# ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAvBgkqhkiG9w0BCQQxIgQgVIcM
# Xw6UcdSZJmo115rJVh+27VsnYXWjzTRiLDncpbQwDQYJKoZIhvcNAQEBBQAEggGA
# iDpLHP2+qz8vQlw/VV5D6EfWzeJwbwdLWfGNYefLXlzBu9JUeERftQvYpc9Y6btr
# WQetsvN6d3tsL19Sjb3vtIueqUoTeHJewWU5v+sFjZwIOsq+RCjBg1wJMEIy/i20
# HFJU5HS2f0OHNlzwBNzrW5FezjxbOg3OQOnYZbY45orEA2O0pzUoBjJ4EjWMD9MN
# nPKvYJATRMAtROLdQfJrVwCZNKuDrRZ2NokhPlGb9Vuy8P16+F6sF3Y3RzASAs1c
# XdmNoHjV/RIbZ1NoIwvrMpdCfxasAzlm/OvNQh7IMkLQWLBbsjrXg8ftYtZvIuvf
# kWG0g0OPZ1Mry2gPU/OKAtAdETd0wG3fRWob3BjhxmnvQBCQPcrbdVHAEZfrCTxR
# mk8DzMPgd1icyvoUoy5WgqoiDFOfgtsUJIr4qLpAkY3nBpypQ3vR9Lx/8radvmFj
# fvqoWD5plEubewIQOY1nK0D9ixy7fHu6xtCg2+1GpDWn3N2147NDhtLE6xmCB6cH
# oYIYFDCCGBAGCisGAQQBgjcDAwExghgAMIIX/AYJKoZIhvcNAQcCoIIX7TCCF+kC
# AQMxDzANBglghkgBZQMEAgEFADCCAWIGCyqGSIb3DQEJEAEEoIIBUQSCAU0wggFJ
# AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIEDm1P+heAxUVJonPr/z
# zPvxtr5pCeceFAMz3GBN8OV6AgZp6IE48vIYEzIwMjYwNTIxMTczMzM5LjQwNlow
# BIACAfSggeGkgd4wgdsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNV
# BAsTHm5TaGllbGQgVFNTIEVTTjo3RDAwLTA1RTAtRDk0NzE1MDMGA1UEAxMsTWlj
# cm9zb2Z0IFB1YmxpYyBSU0EgVGltZSBTdGFtcGluZyBBdXRob3JpdHmggg8hMIIH
# gjCCBWqgAwIBAgITMwAAAAXlzw//Zi7JhwAAAAAABTANBgkqhkiG9w0BAQwFADB3
# MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMUgw
# RgYDVQQDEz9NaWNyb3NvZnQgSWRlbnRpdHkgVmVyaWZpY2F0aW9uIFJvb3QgQ2Vy
# dGlmaWNhdGUgQXV0aG9yaXR5IDIwMjAwHhcNMjAxMTE5MjAzMjMxWhcNMzUxMTE5
# MjA0MjMxWjBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBp
# bmcgQ0EgMjAyMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJ5851Jj
# /eDFnwV9Y7UGIqMcHtfnlzPREwW9ZUZHd5HBXXBvf7KrQ5cMSqFSHGqg2/qJhYqO
# QxwuEQXG8kB41wsDJP5d0zmLYKAY8Zxv3lYkuLDsfMuIEqvGYOPURAH+Ybl4SJEE
# Snt0MbPEoKdNihwM5xGv0rGofJ1qOYSTNcc55EbBT7uq3wx3mXhtVmtcCEr5ZKTk
# KKE1CxZvNPWdGWJUPC6e4uRfWHIhZcgCsJ+sozf5EeH5KrlFnxpjKKTavwfFP6Xa
# GZGWUG8TZaiTogRoAlqcevbiqioUz1Yt4FRK53P6ovnUfANjIgM9JDdJ4e0qiDRm
# 5sOTiEQtBLGd9Vhd1MadxoGcHrRCsS5rO9yhv2fjJHrmlQ0EIXmp4DhDBieKUGR+
# eZ4CNE3ctW4uvSDQVeSp9h1SaPV8UWEfyTxgGjOsRpeexIveR1MPTVf7gt8hY64X
# NPO6iyUGsEgt8c2PxF87E+CO7A28TpjNq5eLiiunhKbq0XbjkNoU5JhtYUrlmAbp
# xRjb9tSreDdtACpm3rkpxp7AQndnI0Shu/fk1/rE3oWsDqMX3jjv40e8KN5YsJBn
# czyWB4JyeeFMW3JBfdeAKhzohFe8U5w9WuvcP1E8cIxLoKSDzCCBOu0hWdjzKNu8
# Y5SwB1lt5dQhABYyzR3dxEO/T1K/BVF3rV69AgMBAAGjggIbMIICFzAOBgNVHQ8B
# Af8EBAMCAYYwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFGtpKDo1L0hjQM97
# 2K9J6T7ZPdshMFQGA1UdIARNMEswSQYEVR0gADBBMD8GCCsGAQUFBwIBFjNodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0w
# EwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEw
# DwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTIftJqhSobyhmYBAcnz1AQT2io
# ojCBhAYDVR0fBH0wezB5oHegdYZzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jcmwvTWljcm9zb2Z0JTIwSWRlbnRpdHklMjBWZXJpZmljYXRpb24lMjBS
# b290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDIwLmNybDCBlAYIKwYB
# BQUHAQEEgYcwgYQwgYEGCCsGAQUFBzAChnVodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMElkZW50aXR5JTIwVmVyaWZpY2F0
# aW9uJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAyMC5jcnQw
# DQYJKoZIhvcNAQEMBQADggIBAF+Idsd+bbVaFXXnTHho+k7h2ESZJRWluLE0Oa/p
# O+4ge/XEizXvhs0Y7+KVYyb4nHlugBesnFqBGEdC2IWmtKMyS1OWIviwpnK3aL5J
# edwzbeBF7POyg6IGG/XhhJ3UqWeWTO+Czb1c2NP5zyEh89F72u9UIw+IfvM9lzDm
# c2O2END7MPnrcjWdQnrLn1Ntday7JSyrDvBdmgbNnCKNZPmhzoa8PccOiQljjTW6
# GePe5sGFuRHzdFt8y+bN2neF7Zu8hTO1I64XNGqst8S+w+RUdie8fXC1jKu3m9KG
# IqF4aldrYBamyh3g4nJPj/LR2CBaLyD+2BuGZCVmoNR/dSpRCxlot0i79dKOChmo
# ONqbMI8m04uLaEHAv4qwKHQ1vBzbV/nG89LDKbRSSvijmwJwxRxLLpMQ/u4xXxFf
# R4f/gksSkbJp7oqLwliDm/h+w0aJ/U5ccnYhYb7vPKNMN+SZDWycU5ODIRfyoGl5
# 9BsXR/HpRGtiJquOYGmvA/pk5vC1lcnbeMrcWD/26ozePQ/TWfNXKBOmkFpvPE8C
# H+EeGGWzqTCjdAsno2jzTeNSxlx3glDGJgcdz5D/AAxw9Sdgq/+rY7jjgs7X6fqP
# TXPmaCAJKVHAP19oEjJIBwD1LyHbaEgBxFCogYSOiUIr0Xqcr1nJfiWG2GwYe6Zo
# AF1bMIIHlzCCBX+gAwIBAgITMwAAAFXZ3WkmKPn44gAAAAAAVTANBgkqhkiG9w0B
# AQwFADBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcg
# Q0EgMjAyMDAeFw0yNTEwMjMyMDQ2NDlaFw0yNjEwMjIyMDQ2NDlaMIHbMQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3Nv
# ZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046
# N0QwMC0wNUUwLUQ5NDcxNTAzBgNVBAMTLE1pY3Jvc29mdCBQdWJsaWMgUlNBIFRp
# bWUgU3RhbXBpbmcgQXV0aG9yaXR5MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAvbkfkh5ZSLP0MCUWafaw/KZoVZu9iQx8r5JwhZvdrUi86UjCCFQONjQa
# nrIxGF9hRGIZLQZ50gHrLC+4fpUEJff5t04VwByWC2/bWOuk6NmaTh9JpPZDcGzN
# R95QlryjfEjtl+gxj12zNPEdADPplVfzt8cYRWFBx/Fbfch08k6P9p7jX2q1jFPb
# UxWYJ+xOyGC1aKhDGY5b+8wL39v6qC0HFIx/v3y+bep+aEXooK8VoeWK+szfaFjX
# o8YTcvQ8UL4szu9HFTuZNv6vvoJ7Ju+o5aTj51sph+0+FXW38TlL/rDBd5ia79js
# kLtOeHbDjkbljilwzegcxv9i49F05ZrS/5ELZCCY1VaqO7EOLKVaxxdAO5oy1vb0
# Bx0ZRVX1mxFjYzay2EC051k6yGJHm58y1oe2IKRa/SM1+BTGse6vHNi5Q2d5ZnoR
# 9AOAUDDwJIIqRI4rZz2MSinh11WrXTG9urF2uoyd5Ve+8hxes9ABeP2PYQKlXYTA
# xvdaeanDTQ/vwmnM+yTcWzrVm84Z38XVFw4G7p/ZNZ2nscvv6uru2AevXcyV1t8h
# a7iWmhhgTWBNBrViuDlc3iPvOz2SVPbPeqhyY/NXwNZCAgc2H5pOztu6MwQxDIjt
# e3XM/FkKBxHofS2abNT/0HG+xZtFqUJDaxgbJa6lN1zh7spjuQ8CAwEAAaOCAcsw
# ggHHMB0GA1UdDgQWBBRWBF8QbdwIA/DIv6nJFsrB16xltjAfBgNVHSMEGDAWgBRr
# aSg6NS9IY0DPe9ivSek+2T3bITBsBgNVHR8EZTBjMGGgX6BdhltodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBQdWJsaWMlMjBS
# U0ElMjBUaW1lc3RhbXBpbmclMjBDQSUyMDIwMjAuY3JsMHkGCCsGAQUFBwEBBG0w
# azBpBggrBgEFBQcwAoZdaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# ZXJ0cy9NaWNyb3NvZnQlMjBQdWJsaWMlMjBSU0ElMjBUaW1lc3RhbXBpbmclMjBD
# QSUyMDIwMjAuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUH
# AwgwDgYDVR0PAQH/BAQDAgeAMGYGA1UdIARfMF0wUQYMKwYBBAGCN0yDfQEBMEEw
# PwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9j
# cy9SZXBvc2l0b3J5Lmh0bTAIBgZngQwBBAIwDQYJKoZIhvcNAQEMBQADggIBAFIe
# 4ZJUe9qUKcWeWypchB58fXE/ZIWv2D5XP5/k/tB7LCN9BvmNSVKZ3VeclQM978wf
# EvuvdMQSUv6Y20boIM8DK1K1IU9cP21MG0ExiHxaqjrikf2qbfrXIip4Ef3v2bNY
# KQxCxN3Sczp1SX0H7uqK2L5OhfDEiXf15iou5hh+EPaaqp49czNQpJDOR/vfJghU
# c/qcslDPhoCZpZx8b2ODvywGQNXwqlbsmCS24uGmEkQ3UH5JUeN6c91yasVchS78
# riMrm6R9ZpAiO5pfNKMGU2MLm1A3pp098DcbFTAc95Hh6Qvkh//28F/Xe2bMFb6D
# L7Sw0ZO95v0gv0ZTyJfxS/LCxfraeEII9FSFOKAMEp1zNFSs2ue0GGjBt9yEEMUw
# vxq9ExFz0aZzYm8ivJfffpIVDnX/+rVRTYcxIkQyFYslIhYlWF9SjCw5r49qakjM
# RNh8W9O7aaoolSVZleQZjGt0K8JzMlyp6hp2lbW6XqRx2cOHbbxJDxmENzohGUzi
# I13lI2g2Bf5qibfC4bKNRpJo9lbE8HUbY0qJiE8u3SU8eDQaySPXOEhJjxRCQwwO
# vejYmBG5P7CckQNBSnnl12+FKRKgPoj0Mv+z5OMhj9z2MtpbnHLAkep0odQClEyy
# CG/uR5tK5rW6mZH5Oq56UWS0NI6NV1JGS7Jri6jFMYIHRjCCB0ICAQEweDBhMQsw
# CQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYD
# VQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMAIT
# MwAAAFXZ3WkmKPn44gAAAAAAVTANBglghkgBZQMEAgEFAKCCBJ8wEQYLKoZIhvcN
# AQkQAg8xAgUAMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0B
# CQUxDxcNMjYwNTIxMTczMzM5WjAvBgkqhkiG9w0BCQQxIgQgGew1FH8DdpTD0YU5
# KMdMuoJzpadSpkTyV7XAyr15kw4wgbkGCyqGSIb3DQEJEAIvMYGpMIGmMIGjMIGg
# BCDYuTyXZIZiu799/v4PaqsmeSzBxh0rqkYq7sYYavj+zTB8MGWkYzBhMQswCQYD
# VQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQD
# EylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMAITMwAA
# AFXZ3WkmKPn44gAAAAAAVTCCA2EGCyqGSIb3DQEJEAISMYIDUDCCA0yhggNIMIID
# RDCCAiwCAQEwggEJoYHhpIHeMIHbMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046N0QwMC0wNUUwLUQ5NDcxNTAzBgNV
# BAMTLE1pY3Jvc29mdCBQdWJsaWMgUlNBIFRpbWUgU3RhbXBpbmcgQXV0aG9yaXR5
# oiMKAQEwBwYFKw4DAhoDFQAdO1QBgmW/tuBZV5EGjhfsV4cN6qBnMGWkYzBhMQsw
# CQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYD
# VQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMDAN
# BgkqhkiG9w0BAQsFAAIFAO25OvAwIhgPMjAyNjA1MjEwODA0MDBaGA8yMDI2MDUy
# MjA4MDQwMFowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA7bk68AIBADAKAgEAAgIa
# DgIB/zAHAgEAAgISqDAKAgUA7bqMcAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgor
# BgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBCwUA
# A4IBAQCICSHSIuaxOenS2KlJgAyygdUgu3w7nS8XrtchXg6VdbyXnRYlu3MpMjuG
# bUtRkHFJX4gxIVsS0pEmbuqwbnTIKE0qQwqKAJ6brR967DrVYoNRYlXPkrKsEk3N
# oi/FOFi5G415msCFHNQxqaPeFi3BNQUCh+stgbHmUOs+c6jDYwTvpn3w90otT+Dw
# oLG00uZNYXzmFJ/cBCYnN6UDDeM0i8qXbg/sL4JM3SyVxsgBg6Bl4+uAX/xddHmE
# 15QISc2ugBHbowTHNL+GIQmBF71fGe6gjag0mPpCswp+w2cF2QkeoX8J7c4R1FoB
# CcJRqE23yQaD5EpWYbxxFJX3yUPKMA0GCSqGSIb3DQEBAQUABIICAFM+tZRfP3Xg
# Y4LTsUV7DwO0Rn8nQpNvi9D//sZ+djtIVuGft4Cfrg7OWmCGslyAxpC/jsyoQ4Yl
# xM65vQaEzGMCYEPxn2mDgJszHebKmwkbgFyGMScjrOnu4ph1LJPW0smFEm9Xvuyy
# TZaCU+gMijXETrMQ4++1a0CuYIQ+pbgt54Tl8tYMimz+H8GWWQ8/WYSgOK1cHPbo
# 9ofTc+5NVuMMtrceZ5YhybFvlRgIP/kxqipPpxK76APxjFve0PEWe2Rvny6jXByC
# 8iYaSNgMyL/ReOMVW6KFkZREXdEZvKQOJfiLLRs86L2lw1FNc72pmO8aeV7rMzzb
# AuFEhk7LFq5NjhAC/cp1rJeU+dSUHy1yiEXzOOifcVnjzKCBeRJosVnY/E2Vamg6
# 02leE5ZB7y12J6sfE+npr9MWjF2QVVmGO0WKOxrXOzFQRDQbxRSCT5czYdmsPemM
# s7/B8RVMkg0YtPkKNJ8edMky6Ae9l+n0oJBiC2rxVS2cE2HVyNkYcUgTJAAjw8gf
# VmB6kZZgjr5BDLSGlpd/YNTY2kD6drwb7D20ABWjQhIuktpDvgB850u3uQc2xi/L
# TScUyCDc2Y0K+Shu2Mw9WMpFnYAa+bePpnrrLsPTJRbUor1as6BAZL7MEosN12r/
# 8qlUJaxQLoGhBQ3FiSyBOowdcM6vgbI6
# SIG # End signature block
