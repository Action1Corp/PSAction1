# Name: PSAction1
# Description: Powershell module for working with the Action1 API.
# Copyright (C) 2026 Action1 Corporation
# Documentation: https://github.com/Action1Corp/PSAction1/
# Use Action1 Roadmap system (https://roadmap.action1.com/) to submit feedback or enhancement requests.

# WARNING: Carefully study the provided scripts and components before using them. Test in your non-production lab first.

# LIMITATION OF LIABILITY. IN NO EVENT SHALL ACTION1 OR ITS SUPPLIERS, OR THEIR RESPECTIVE 
# OFFICERS, DIRECTORS, EMPLOYEES, OR AGENTS BE LIABLE WITH RESPECT TO THE WEBSITE OR
# THE COMPONENTS OR THE SERVICES UNDER ANY CONTRACT, NEGLIGENCE, TORT, STRICT 
# LIABILITY OR OTHER LEGAL OR EQUITABLE THEORY (I)FOR ANY AMOUNT IN THE AGGREGATE IN
# EXCESS OF THE GREATER OF FEES PAID BY YOU THEREFOR OR $100; (II) FOR ANY INDIRECT,
# INCIDENTAL, PUNITIVE, OR CONSEQUENTIAL DAMAGES OF ANY KIND WHATSOEVER; (III) FOR
# DATA LOSS OR COST OF PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; OR (IV) FOR ANY
# MATTER BEYOND ACTION1’S REASONABLE CONTROL. SOME STATES DO NOT ALLOW THE
# EXCLUSION OR LIMITATION OF INCIDENTAL OR CONSEQUENTIAL DAMAGES, SO THE ABOVE
# LIMITATIONS AND EXCLUSIONS MAY NOT APPLY TO YOU.

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

function CheckToken() {
    if (($null -ne $Script:Action1_Token) -and ($Script:Action1_Token.expires_at -ge $(Get-Date))) {
        Debug-Host "Current token is valid."
        return $true
    }
    else {
        Debug-Host "Token not set or expired, fetching new."
        if (FetchToken -ne $null ) {
            Debug-Host "Token refresh successful."
            return $true
        }
        else {
            Write-Error "Token could not be refreshed, check for errors in output."
            return $false
        }
    }
}

function CheckRoot {
    if ($Script:Action1_BaseURI -eq '') {
        if ($Script:Action1_Interactive) {
            while ($Script:Action1_BaseURI -eq '') {
                0..($Action1_Hosts.Count - 1) | `
                    ForEach-Object {
                    Write-Host "$($_) : $($($Action1_Hosts.Keys -Split '`n')[$_])" }; 
                $Script:Action1_BaseURI = $($Action1_Hosts.Values -Split '`n')[[int]::Parse($(Read-Host -Prompt 'Select your data center region.'))]

            }
            return $true
        }
        else {
            Write-Error "Region not set, call Set-Action1Region prior to making any calls to the API."
            exit
        }
    }
    return $true
}
function CheckOrg {
    if ($null -eq $Script:Action1_Default_Org) {
        if ($Script:Action1_Interactive) {
            while ($null -eq $Script:Action1_Default_Org) { Set-Action1DefaultOrg }
        }
        else {
            Write-Error "Default Org not set, call Set-Action1DefaultOrg prior to making any calls to the API."
            exit
        }
    }
    return $Script:Action1_Default_Org 
}
function FetchToken {
    if (CheckRoot) {
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
            $Token = (ConvertFrom-Json -InputObject (Invoke-WebRequest -Uri "$Script:Action1_BaseURI/oauth2/token" -Method POST -UseBasicParsing -Body @{client_id = $Script:Action1_APIKey; client_secret = $Script:Action1_Secret }).Content )  
            $Token | Add-Member -MemberType NoteProperty -Name "expires_at" -Value $(Get-Date).AddSeconds(([int]$Token.expires_in - 5)) #Expire token 5 seconds early to avoid race condition timeouts.
            $Script:Action1_Token = $Token
            return $Token
        }
        catch [System.Net.WebException] {
            Write-Error "Error fetching auth token: $($_)."
            Write-Error $Token
            return $null
        }     
    }
}

function BuildArgs {
    param (
        [String]$In,
        [String]$Add
    )
    if ([string]::IsNullOrEmpty($In)) { return $Add }else { return "$In&$Add" }
}

function DoGet {
    param (
        [Parameter(Mandatory)]
        [String]$Path,
        [Parameter(Mandatory)]
        [String]$Label,
        [String]$AddArgs,
        [switch]$Raw
    )
    try {
        if ($AddArgs) { $Path += "?{0}" -f $AddArgs }
        Debug-Host "GET request to $Path : Raw flag is $Raw"
        if ($Raw) {
            return (Invoke-WebRequest -Uri $Path -Method GET -UseBasicParsing -Headers @{Authorization = "Bearer $(($Script:Action1_Token).access_token)"; 'Content-Type' = 'application/json; charset=utf-8' }).Content
        }
        else { 
            return (ConvertFrom-Json -InputObject (Invoke-WebRequest -Uri $Path -Method GET -UseBasicParsing -Headers @{Authorization = "Bearer $(($Script:Action1_Token).access_token)"; 'Content-Type' = 'application/json; charset=utf-8' }).Content ) 
        } 
    }
    catch [System.Net.WebException] {
        Write-Error "Error fetching $($Label): $($_)."
        return $null
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
    if ($FileData.Length -lt $BufferSize) { $BufferSize = $FileData.Length; Debug-Host "File is smaller than BufferSize, adjusting to $($FileData.Length)" }
    $Buffer = New-Object byte[] $BufferSize
    $Place = 0

    $HeaderBase = @{
        'accept'                = '*/*'
        'X-Upload-Content-Type' = 'application/octet-stream'
    }
    try {
        $Headers = $HeaderBase.Clone()
        $Headers.Add('X-Upload-Content-Length', $($FileData.Length))
        $Headers.Add('Content-Type', 'application/json')
        if (CheckToken) { $Headers.Add('Authorization', "Bearer $(($Script:Action1_Token).access_token)"); Invoke-WebRequest -Uri $uri -Method Post -UseBasicParsing -Headers $Headers -ErrorAction SilentlyContinue }
    }
    catch { $UploadTarget = $_.Exception.Response.Headers['X-Upload-Location'] } 
    Debug-Host "Upload URI is $UploadTarget"
    while (($Read = $FileData.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
        $Headers = $HeaderBase.Clone()
        $Headers.Add('Content-Range', "bytes $($Place)-$($($Place + $Read-1))/$($FileData.Length)")
        $Headers.Add('Content-Length', "$($Read)")
        $Headers.Add('Content-Type', 'application/octet-stream')
        $Place += $Read
        try { if (CheckToken) { $Headers.Add('Authorization', "Bearer $(($Script:Action1_Token).access_token)"); $response = Invoke-WebRequest -Method Put -UseBasicParsing -Uri $UploadTarget -Body $Buffer -Headers $Headers -ErrorAction SilentlyContinue } }
        catch { Debug-Host "Last Status: $($_.Exception.Response.StatusCode)" }
        if (($FileData.Length - $Place) -lt $BufferSize) { $buffer = New-Object byte[] ($FileData.Length - $place) }
        Debug-Host "Upload $([math]::Round((($Place / $FileData.Length)*100),1))% Complete."
        if ($Buffer.Length -eq 0) { Debug-Host "Final Status:$($response.StatusCode)" }else { Debug-Host "Bytes Written: $($Buffer.Length)" }
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

function PushData {
    param (
        [Parameter(Mandatory)]
        [ValidateSet(
            'PATCH',
            'POST',
            'DELETE'
        )]
        [string]$Method,
        [Parameter(Mandatory)]
        [String]$Path,
        [Parameter(Mandatory)]
        [String]$Label,
        [object]$Body
    )
    try {
        Debug-Host "$Method request to $Path."
        if ($data) { Debug-Host "Data to be sent:`n $(ConvertTo-Json -InputObject $Body -Depth 10)" }
        return (ConvertFrom-Json -InputObject (Invoke-WebRequest -Uri $Path -Method $Method -UseBasicParsing -Body (ConvertTo-Json -InputObject $Body -Depth 10) -Headers @{Authorization = "Bearer $(($Script:Action1_Token).access_token)"; 'Content-Type' = 'application/json; charset=utf-8' }).Content)
    }
    catch [System.Net.WebException] {
        Write-Error "Error processing $($Label): $($_)"
        return $null
    } 
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
    if ($Query -eq 'RawURI') { if (!$URI) { Write-Error "Error -URI value required when Query is type RawURI.`n"; return $null }else { if (CheckToken) { return DoGet -Path $URI -Label $Query } } }
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

    if (CheckToken) {
        $AddArgs = ""
        $sbPolicyResultsDetail = {
            $Page = DoGet -Path $this.details -Label "PolicyResultsDetails"
            $Page.items | Write-Output
            While (![string]::IsNullOrEmpty($Page.next_page)) {
                $Page = DoGet -Path $Page.next_page -Label "PolicyResultsDetails"
                $Page.items | Write-Output
            }
        }
        $sbCustomFieldGet = { param([string]$name)($this.custom | Where-Object { $_.name -eq $name }).value }

        if ($null -eq $Limit){$Limit=200}
        if ($Limit -gt 0) { $AddArgs = BuildArgs -In $AddArgs -Add "limit=$Limit"}else{$AddArgs = BuildArgs -In $AddArgs -Add "limit=200"}
        #if ($From -gt 0) { $AddArgs = BuildArgs -In $AddArgs -Add "from=$From" }
        #Add more URI arguments here?..
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
                $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["G_$Query"] -Org_ID $(CheckOrg) -Object_ID $Id)
            }
            else {
                $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["G_$Query"] -Org_ID $(CheckOrg))
            }
        } 
        if ($Rawlist.Contains($Query)) { $Page = DoGet -Path $Path -Label $Query -AddArgs $AddArgs -Raw } else { $Page = DoGet -Path $Path -Label $Query -AddArgs $AddArgs }
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
                if ($Rawlist.Contains($Query)) { $Page = DoGet -Path $Page.next_page -Label $Query -Raw } else { $Page = DoGet -Path $Page.next_page -Label $Query }
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
    if ($Item -eq 'RawURI') { if (!$URI) { Write-Error "Error -URI value required when Action is type RawURI.`n"; return $null }else { if (CheckToken) { return PushData -Path $URI -Method POST -Body $Data -Label 'RawRequest'} } }
    if (CheckToken) {
        try {
            if (!$URILookUp["N_$Item"].ToString().Contains("`$Org_ID")) {
                $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["N_$Item"])
            }
            else {
                $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["N_$Item"] -Org_ID $(CheckOrg))
            } 
            return PushData -Method POST -Path $Path -Label $Item -Body $Data
        }
        catch {
            Write-Error "Error adding $Item`: $($_)."
            return $null
        }
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
    if ($Type -eq 'RawURI') { if (!$URI) { Write-Error "Error -URI value required when Action is type RawURI.`n"; return $null }else { if (CheckToken) { return PushData -Path $URI -Method PATCH -Body $Data -Label 'RawRequest'} } }
    if (CheckToken) {
        switch ($Action) {
            'ModifyMembers' {
                switch ($Type) {
                    'EndpointGroup' { 
                        $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["U_GroupMembers"] -Org_ID $(CheckOrg) -Object_ID $id)
                        return PushData -Method POST -Path $Path -Body $Data -Label "$Action=>$Type"
                    }
                    default { Write-Error "Invalid request of $Type for query $Action." ; return $null }
                }
            }
            'Modify' {              
                if (!$Id) { Write-Error "When perfoming $Action=>$Type, the value for -Id must be specified to know what object to act on."; return $null } 
                switch ($Type) {
                    'Automation' {
                        $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["U_Automation"] -Org_ID $(CheckOrg) -Object_Id $Id)
                        return PushData -Method PATCH -Path $Path -Body $Data -Label "$Action=>$Type" 
                    }
                    'CustomAttribute' {
                        $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["U_Endpoint"] -Org_ID $(CheckOrg) -Object_Id $Id)
                        $Data = New-Object psobject -Property @{"custom:$AttributeName" = $AttributeValue }
                        return PushData -Method PATCH -Path $Path -Body $Data -Label "$Action=>$Type" 
                    }
                    'Endpoint' { 
                        $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["U_Endpoint"] -Org_ID $(CheckOrg) -Object_Id $Id)
                        $Data.PSObject.Members | ForEach-Object { if (@('name', 'comment') -notcontains $_.Name) { $Data.PSObject.Members.Remove($_.Name) } }
                        return PushData -Method PATCH -Path $Path -Body $Data -Label "$Action=>$Type" 
                    }
                    'EndpointGroup' { 
                        $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["U_GroupModify"] -Org_ID $(CheckOrg) -Object_Id $Id)
                        return PushData -Method PATCH -Path $Path -Body $Data -Label "$Action=>$Type"
                    }
                    default { Write-Error "Invalid request of $Type for query $Action." ; return $null }
                }   
            }
            'Delete' {
                Debug-Host "Force delete enabled:$Force."
                switch ($Type) {
                    'EndpointGroup' { 
                        if ($force -or ((Read-Host "Are you sure you want to $Action $Type [$id]?`n[Y]es to confirm, any other key to cancel.") -eq 'Y')) {
                            $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["U_GroupModify"] -Org_ID $(CheckOrg) -Object_Id $Id)
                            return PushData -Method DELETE -Path $Path -Label "$Action=>$Type"
                        }
                    }
                    'Endpoint' { 
                        if ($force -or ((Read-Host "Are you sure you want to $Action $Type [$id]?`n[Y]es to confirm, any other key to cancel.") -eq 'Y')) {
                            $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["U_Endpoint"] -Org_ID $(CheckOrg) -Object_Id $Id)
                            return PushData -Method DELETE -Path $Path -Label "$Action=>$Type"
                        }
                    }
                    'Automation' {
                        if ($force -or ((Read-Host "Are you sure you want to $Action $Type [$id]?`n[Y]es to confirm, any other key to cancel.") -eq 'Y')) {
                            $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["U_Automation"] -Org_ID $(CheckOrg) -Object_Id $Id)
                            return PushData -Method DELETE -Path $Path -Label "$Action=>$Type"
                        }
                    }
                    default { Write-Error "Invalid request of $Type for query $Action." ; return $null }
                }
            }
            default { Write-Error "Invalid request of $Type for query $Action." ; return $null }
        }
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
    if (CheckToken) {
        if (!$URILookUp["R_$Type"].ToString().Contains("`$Org_ID")) {
            $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["R_$Type"])
        }
        else {
            if ($Endpoint_Id) {
                if ($URILookUp["R_$Type"].ToString().Contains("`$Object_ID")) {
                    $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["R_$Type"] -Org_ID $(CheckOrg) -Object_ID $Endpoint_Id)
                }
                else {
                    Write-Error "Endpoint_Id was specified but this action is not endpoint specific, can continue, defaulting to system wide."
                    $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["R_$Type"] -Org_ID $(CheckOrg))
                } 
            }
            else {
                $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["R_$Type"] -Org_ID $(CheckOrg))
            }
        } 
        return PushData -Method POST -Path $Path.TrimEnd('/') -Label "Requery=>$Type"
    }
}


# SIG # Begin signature block
# MII96wYJKoZIhvcNAQcCoII93DCCPdgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBUQPP6BvFmpiIh
# R1JVGIvqS1Cb9XVjPZ02sQBhOcRGraCCIrAwggXMMIIDtKADAgECAhBUmNLR1FsZ
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
# 03u4aUoqlmZpxJTG9F9urJh4iIAGXKKy7aIwggbsMIIE1KADAgECAhMzAAe8E8Zf
# DI+rQz3HAAAAB7wTMA0GCSqGSIb3DQEBDAUAMFoxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDUyBFT0MgQ0EgMDEwHhcNMjYwMzMwMTQyNTU2WhcNMjYwNDAy
# MTQyNTU2WjBrMQswCQYDVQQGEwJVUzEOMAwGA1UECBMFVGV4YXMxEDAOBgNVBAcT
# B0hvdXN0b24xHDAaBgNVBAoTE0FjdGlvbjEgQ29ycG9yYXRpb24xHDAaBgNVBAMT
# E0FjdGlvbjEgQ29ycG9yYXRpb24wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQDeg9jgofFKtvzL98o6wjb4aX22nes3kl1fQ0r0MSz6/MCRwqt97uMjLlbl
# UAsolSHOsXsBpnU8ElPLkEBQ8qAXYzwQRJVm64AgmxI24x9NwQOtp7v4Tz2EMXbE
# Kafoeq9CoOvLFLvFhAYzkAA+3NgePIEKQuqJ9nmuF7vq7qFIKA/G9GNQgIZwz0x5
# yISkpeuuXavOK6KubpFmRiyrIAbOM6EJgaxwksQ336yJFDiTixL4SPZQf0hOWFz9
# +iHV4Y/nu9htc31mMuTGmrnp2ayoSG+dJv7U1jlrtnefv+LPHZAZgOStzruuPMmi
# M/p5sz1FoAYDVjUxpne3RPoRuLkrda4TR1NsbKbNHXU20zI5VlVnSuzv2C4sL/g8
# DHRQKOC93OWvXMhFBP7tLNxDG6Jlf7LDzdtNd0AF3ZSjGcAWlg9/Q/7PY02hoL2+
# plvavNaMFcupOCI13ce6H8iqLk0BQzAc9Inv8IWioIAdBIYODqp2xhXZD1FzDQ08
# uOhPGI8CAwEAAaOCAhgwggIUMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeA
# MDsGA1UdJQQ0MDIGCisGAQQBgjdhAQAGCCsGAQUFBwMDBhorBgEEAYI3YYTGyjWC
# 84fIeoPTzfIboMPaLTAdBgNVHQ4EFgQUIESqFE7zJAZYSTNy+nGAB88ORb4wHwYD
# VR0jBBgwFoAUdpw2dBPRkH1hX7MC64D0mUulPoUwZwYDVR0fBGAwXjBcoFqgWIZW
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# SUQlMjBWZXJpZmllZCUyMENTJTIwRU9DJTIwQ0ElMjAwMS5jcmwwgaUGCCsGAQUF
# BwEBBIGYMIGVMGQGCCsGAQUFBzAChlhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUyMEVP
# QyUyMENBJTIwMDEuY3J0MC0GCCsGAQUFBzABhiFodHRwOi8vb25lb2NzcC5taWNy
# b3NvZnQuY29tL29jc3AwZgYDVR0gBF8wXTBRBgwrBgEEAYI3TIN9AQEwQTA/Bggr
# BgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1Jl
# cG9zaXRvcnkuaHRtMAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAWVgkSIxU
# bv74c+PUvtgyyEzCcclNRdI09jvtsdoiZXhTAXEL6JbzIROoBgWeBYG86sKn9O5+
# X/VDFedVP/Q12aL7z9M47gHYhHUAAeSyc7gZ4ETt7lBzjMB0LOqtQ+QFJbaktr6l
# y9il9JWLJtav2G49+yo16CP9KruHA/lWLYX3FGd3ohpWluEAprkHExc5y/ajy9Q5
# GhcwSrfpLLgI60ZpzgXt7yHRJ6XnsMWgrdlEmpjfku7f+RlDliSUW3S0XdVdrWuI
# cumGharz66ZSIadl8zgBlWxTa7i8PUrd5PHlXLf5/4rC7Dx+46ceS4r+lKsvycFT
# 3LehcQwZLHxBbGiPkUMB3OSnMJOmMo256YAuqzblzeNfUi8ZBShQ+aldljZQTh8E
# hA5f7TI8WdmmmVTszsCv7sH0pgWLjigxYqxrmKNSCDZvGPW9qc6JO4Gl11hmbi7x
# mb8+WYgUH571jf36mr9id2ofXxuevMRVJWkU3cLyWPr8Oule7WJfkeTxovJK2q49
# JOnO0HTqbFe+MUWEmmDd2Zxvv0Vfz6pCwAZnFjux4aCTI3CD6ywlRGdkiYQO0TpS
# dbD9SZCmRnarH3TJZM/ee259u7NmkTAOlGTFO6zGO5N5MyPUketn8EdlZPc+VprO
# IAlKQizzEFqUKL5nNFXcjr1/xxSU4/pcIQAwggbsMIIE1KADAgECAhMzAAe8E8Zf
# DI+rQz3HAAAAB7wTMA0GCSqGSIb3DQEBDAUAMFoxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDUyBFT0MgQ0EgMDEwHhcNMjYwMzMwMTQyNTU2WhcNMjYwNDAy
# MTQyNTU2WjBrMQswCQYDVQQGEwJVUzEOMAwGA1UECBMFVGV4YXMxEDAOBgNVBAcT
# B0hvdXN0b24xHDAaBgNVBAoTE0FjdGlvbjEgQ29ycG9yYXRpb24xHDAaBgNVBAMT
# E0FjdGlvbjEgQ29ycG9yYXRpb24wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQDeg9jgofFKtvzL98o6wjb4aX22nes3kl1fQ0r0MSz6/MCRwqt97uMjLlbl
# UAsolSHOsXsBpnU8ElPLkEBQ8qAXYzwQRJVm64AgmxI24x9NwQOtp7v4Tz2EMXbE
# Kafoeq9CoOvLFLvFhAYzkAA+3NgePIEKQuqJ9nmuF7vq7qFIKA/G9GNQgIZwz0x5
# yISkpeuuXavOK6KubpFmRiyrIAbOM6EJgaxwksQ336yJFDiTixL4SPZQf0hOWFz9
# +iHV4Y/nu9htc31mMuTGmrnp2ayoSG+dJv7U1jlrtnefv+LPHZAZgOStzruuPMmi
# M/p5sz1FoAYDVjUxpne3RPoRuLkrda4TR1NsbKbNHXU20zI5VlVnSuzv2C4sL/g8
# DHRQKOC93OWvXMhFBP7tLNxDG6Jlf7LDzdtNd0AF3ZSjGcAWlg9/Q/7PY02hoL2+
# plvavNaMFcupOCI13ce6H8iqLk0BQzAc9Inv8IWioIAdBIYODqp2xhXZD1FzDQ08
# uOhPGI8CAwEAAaOCAhgwggIUMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeA
# MDsGA1UdJQQ0MDIGCisGAQQBgjdhAQAGCCsGAQUFBwMDBhorBgEEAYI3YYTGyjWC
# 84fIeoPTzfIboMPaLTAdBgNVHQ4EFgQUIESqFE7zJAZYSTNy+nGAB88ORb4wHwYD
# VR0jBBgwFoAUdpw2dBPRkH1hX7MC64D0mUulPoUwZwYDVR0fBGAwXjBcoFqgWIZW
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# SUQlMjBWZXJpZmllZCUyMENTJTIwRU9DJTIwQ0ElMjAwMS5jcmwwgaUGCCsGAQUF
# BwEBBIGYMIGVMGQGCCsGAQUFBzAChlhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUyMEVP
# QyUyMENBJTIwMDEuY3J0MC0GCCsGAQUFBzABhiFodHRwOi8vb25lb2NzcC5taWNy
# b3NvZnQuY29tL29jc3AwZgYDVR0gBF8wXTBRBgwrBgEEAYI3TIN9AQEwQTA/Bggr
# BgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1Jl
# cG9zaXRvcnkuaHRtMAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAWVgkSIxU
# bv74c+PUvtgyyEzCcclNRdI09jvtsdoiZXhTAXEL6JbzIROoBgWeBYG86sKn9O5+
# X/VDFedVP/Q12aL7z9M47gHYhHUAAeSyc7gZ4ETt7lBzjMB0LOqtQ+QFJbaktr6l
# y9il9JWLJtav2G49+yo16CP9KruHA/lWLYX3FGd3ohpWluEAprkHExc5y/ajy9Q5
# GhcwSrfpLLgI60ZpzgXt7yHRJ6XnsMWgrdlEmpjfku7f+RlDliSUW3S0XdVdrWuI
# cumGharz66ZSIadl8zgBlWxTa7i8PUrd5PHlXLf5/4rC7Dx+46ceS4r+lKsvycFT
# 3LehcQwZLHxBbGiPkUMB3OSnMJOmMo256YAuqzblzeNfUi8ZBShQ+aldljZQTh8E
# hA5f7TI8WdmmmVTszsCv7sH0pgWLjigxYqxrmKNSCDZvGPW9qc6JO4Gl11hmbi7x
# mb8+WYgUH571jf36mr9id2ofXxuevMRVJWkU3cLyWPr8Oule7WJfkeTxovJK2q49
# JOnO0HTqbFe+MUWEmmDd2Zxvv0Vfz6pCwAZnFjux4aCTI3CD6ywlRGdkiYQO0TpS
# dbD9SZCmRnarH3TJZM/ee259u7NmkTAOlGTFO6zGO5N5MyPUketn8EdlZPc+VprO
# IAlKQizzEFqUKL5nNFXcjr1/xxSU4/pcIQAwggdaMIIFQqADAgECAhMzAAAABkoa
# +s8FYWp0AAAAAAAGMA0GCSqGSIb3DQEBDAUAMGMxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xNDAyBgNVBAMTK01pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDb2RlIFNpZ25pbmcgUENBIDIwMjEwHhcNMjEwNDEzMTczMTU0
# WhcNMjYwNDEzMTczMTU0WjBaMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgSUQgVmVyaWZpZWQg
# Q1MgRU9DIENBIDAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAx+PI
# P/Qh3cYZwLvFy6uuJ4fTp3ln7Gqs7s8lTVyfgOJWP1aABwk2/oxdVjfSHUq4MTPX
# ilL57qi/fH7YndEK4Knd3u5cedFwr2aHSTp6vl/PL1dAL9sfoDvNpdG0N/R84AhY
# NpBQThpO4/BqxmCgl3iIRfhh2oFVOuiTiDVWvXBg76bcjnHnEEtXzvAWwJu0bBU7
# oRRqQed4VXJtICVt+ZoKUSjqY5wUlhAdwHh+31BnpBPCzFtKViLp6zEtRyOxRega
# gFU+yLgXvvmd07IDN0S2TLYuiZjTw+kcYOtoNgKr7k0C6E9Wf3H4jHavk2MxqFpt
# gfL0gL+zbSb+VBNKiVT0mqzXJIJmWmqw0K+D3MKfmCer3e3CbrP+F5RtCb0XaE0u
# RcJPZJjWwciDBxBIbkNF4GL12hl5vydgFMmzQcNuodKyX//3lLJ1q22roHVS1cgt
# sLgpjWYZlBlhCTcXJeZ3xuaJvXZB9rcLCX15OgXL21tUUwJCLE27V5AGZxkO3i54
# mgSCswtOmWU4AKd/B/e3KtXv6XBURKuAteez1EpgloaZwQej9l5dN9Uh8W19BZg9
# IlLl+xHRX4vDiMWAUf/7ANe4MoS98F45r76IGJ0hC02EMuMZxAErwZj0ln0aL53E
# zlMa5JCiRObb0UoLHfGSdNJsMg0uj3DAQDdVWTECAwEAAaOCAg4wggIKMA4GA1Ud
# DwEB/wQEAwIBhjAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQUdpw2dBPRkH1h
# X7MC64D0mUulPoUwVAYDVR0gBE0wSzBJBgRVHSAAMEEwPwYIKwYBBQUHAgEWM2h0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0
# bTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTASBgNVHRMBAf8ECDAGAQH/AgEA
# MB8GA1UdIwQYMBaAFNlBKbAPD2Ns72nX9c0pnqRIajDmMHAGA1UdHwRpMGcwZaBj
# oGGGX2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29m
# dCUyMElEJTIwVmVyaWZpZWQlMjBDb2RlJTIwU2lnbmluZyUyMFBDQSUyMDIwMjEu
# Y3JsMIGuBggrBgEFBQcBAQSBoTCBnjBtBggrBgEFBQcwAoZhaHR0cDovL3d3dy5t
# aWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBJRCUyMFZlcmlm
# aWVkJTIwQ29kZSUyMFNpZ25pbmclMjBQQ0ElMjAyMDIxLmNydDAtBggrBgEFBQcw
# AYYhaHR0cDovL29uZW9jc3AubWljcm9zb2Z0LmNvbS9vY3NwMA0GCSqGSIb3DQEB
# DAUAA4ICAQBqLwmf2LB1QjUga0G7zFkbGd8NBQLHP0KOFBWNJFZiTtKfpO0bZ2Wf
# s6v5vqIKjE32Q6M89G4ZkVcvWuEAA+dvjLThSy89Y0//m/WTSKwYtiR1Ewn7x1kw
# /Fg93wQps2C1WUj+00/6uNrF+d4MVJxV1HoBID+95ZIW0KkqZopnOA4w5vP4T5cB
# prZQAlP/vMGyB0H9+pHNo0jT9Q8gfKJNzHS9i1DgBmmufGdW9TByuno8GAizFMhL
# lIs08b5lilIkE5z3FMAUAr+XgII1FNZnb43OI6Qd2zOijbjYfursXUCNHC+RSwJG
# m5ULzPymYggnJ+khJOq7oSlqPGpbr70hGBePw/J7/mmSqp7hTgt0mPikS1i4ap8x
# +P3yemYShnFrgV1752TI+As69LfgLthkITvf7bFHB8vmIhadZCOS0vTCx3B+/OVc
# EMLNO2bJ0O9ikc1JqR0Fvqx7nAwMRSh3FVqosgzBbWnVkQJq7oWFwMVfFIYn6LPR
# ZMt48u6iMUCFBSPddsPA/6k85mEv+08U5WCQ7ydj1KVV2THre/8mLHiem9wf/Czo
# hqRntxM2E/x+NHy6TBMnSPQRqhhNfuOgUDAWEYmlM/ZHGaPIb7xOvfVyLQ/7l6Yf
# ogT3eptwp4GOGRjH5z+gG9kpBIx8QrRl6OilnlxRExokmMflL7l12TCCB54wggWG
# oAMCAQICEzMAAAAHh6M0o3uljhwAAAAAAAcwDQYJKoZIhvcNAQEMBQAwdzELMAkG
# A1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjFIMEYGA1UE
# AxM/TWljcm9zb2Z0IElkZW50aXR5IFZlcmlmaWNhdGlvbiBSb290IENlcnRpZmlj
# YXRlIEF1dGhvcml0eSAyMDIwMB4XDTIxMDQwMTIwMDUyMFoXDTM2MDQwMTIwMTUy
# MFowYzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjE0MDIGA1UEAxMrTWljcm9zb2Z0IElEIFZlcmlmaWVkIENvZGUgU2lnbmluZyBQ
# Q0EgMjAyMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALLwwK8ZiCji
# 3VR6TElsaQhVCbRS/3pK+MHrJSj3Zxd3KU3rlfL3qrZilYKJNqztA9OQacr1AwoN
# cHbKBLbsQAhBnIB34zxf52bDpIO3NJlfIaTE/xrweLoQ71lzCHkD7A4As1Bs076I
# u+mA6cQzsYYH/Cbl1icwQ6C65rU4V9NQhNUwgrx9rGQ//h890Q8JdjLLw0nV+ayQ
# 2Fbkd242o9kH82RZsH3HEyqjAB5a8+Ae2nPIPc8sZU6ZE7iRrRZywRmrKDp5+Tcm
# JX9MRff241UaOBs4NmHOyke8oU1TYrkxh+YeHgfWo5tTgkoSMoayqoDpHOLJs+qG
# 8Tvh8SnifW2Jj3+ii11TS8/FGngEaNAWrbyfNrC69oKpRQXY9bGH6jn9NEJv9weF
# xhTwyvx9OJLXmRGbAUXN1U9nf4lXezky6Uh/cgjkVd6CGUAf0K+Jw+GE/5VpIVbc
# Nr9rNE50Sbmy/4RTCEGvOq3GhjITbCa4crCzTTHgYYjHs1NbOc6brH+eKpWLtr+b
# Gecy9CrwQyx7S/BfYJ+ozst7+yZtG2wR461uckFu0t+gCwLdN0A6cFtSRtR8bvxV
# FyWwTtgMMFRuBa3vmUOTnfKLsLefRaQcVTgRnzeLzdpt32cdYKp+dhr2ogc+qM6K
# 4CBI5/j4VFyC4QFeUP2YAidLtvpXRRo3AgMBAAGjggI1MIICMTAOBgNVHQ8BAf8E
# BAMCAYYwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNlBKbAPD2Ns72nX9c0p
# nqRIajDmMFQGA1UdIARNMEswSQYEVR0gADBBMD8GCCsGAQUFBwIBFjNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wGQYJ
# KwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSME
# GDAWgBTIftJqhSobyhmYBAcnz1AQT2ioojCBhAYDVR0fBH0wezB5oHegdYZzaHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwSWRl
# bnRpdHklMjBWZXJpZmljYXRpb24lMjBSb290JTIwQ2VydGlmaWNhdGUlMjBBdXRo
# b3JpdHklMjAyMDIwLmNybDCBwwYIKwYBBQUHAQEEgbYwgbMwgYEGCCsGAQUFBzAC
# hnVodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29m
# dCUyMElkZW50aXR5JTIwVmVyaWZpY2F0aW9uJTIwUm9vdCUyMENlcnRpZmljYXRl
# JTIwQXV0aG9yaXR5JTIwMjAyMC5jcnQwLQYIKwYBBQUHMAGGIWh0dHA6Ly9vbmVv
# Y3NwLm1pY3Jvc29mdC5jb20vb2NzcDANBgkqhkiG9w0BAQwFAAOCAgEAfyUqnv7U
# q+rdZgrbVyNMul5skONbhls5fccPlmIbzi+OwVdPQ4H55v7VOInnmezQEeW4LqK0
# wja+fBznANbXLB0KrdMCbHQpbLvG6UA/Xv2pfpVIE1CRFfNF4XKO8XYEa3oW8oVH
# +KZHgIQRIwAbyFKQ9iyj4aOWeAzwk+f9E5StNp5T8FG7/VEURIVWArbAzPt9ThVN
# 3w1fAZkF7+YU9kbq1bCR2YD+MtunSQ1Rft6XG7b4e0ejRA7mB2IoX5hNh3UEauY0
# byxNRG+fT2MCEhQl9g2i2fs6VOG19CNep7SquKaBjhWmirYyANb0RJSLWjinMLXN
# OAga10n8i9jqeprzSMU5ODmrMCJE12xS/NWShg/tuLjAsKP6SzYZ+1Ry358ZTFcx
# 0FS/mx2vSoU8s8HRvy+rnXqyUJ9HBqS0DErVLjQwK8VtsBdekBmdTbQVoCgPCqr+
# PDPB3xajYnzevs7eidBsM71PINK2BoE2UfMwxCCX3mccFgx6UsQeRSdVVVNSyALQ
# e6PT12418xon2iDGE81OGCreLzDcMAZnrUAx4XQLUz6ZTl65yPUiOh3k7Yww94lD
# f+8oG2oZmDh5O1Qe38E+M3vhKwmzIeoB1dVLlz4i3IpaDcR+iuGjH2TdaC1ZOmBX
# iCRKJLj4DT2uhJ04ji+tHD6n58vhavFIrmcxghqRMIIajQIBATBxMFoxCzAJBgNV
# BAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMT
# Ik1pY3Jvc29mdCBJRCBWZXJpZmllZCBDUyBFT0MgQ0EgMDECEzMAB7wTxl8Mj6tD
# PccAAAAHvBMwDQYJYIZIAWUDBAIBBQCgXjAQBgorBgEEAYI3AgEMMQIwADAZBgkq
# hkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAvBgkqhkiG9w0BCQQxIgQgLDaqrXzFeTvG
# NXF0NmzZ6ZGqDkiCubh5orR4HCihA8wwDQYJKoZIhvcNAQEBBQAEggGAnn+b1vHJ
# hcjdfJgek3eR0L2jh5O0nA7tZ3pYH5XFVboE5GcESmZ618EaSbjHVcVVWO/cQbDJ
# ctmR8l1gMTpbIb/2cRAc/lrIxOEsUY3RziCB8/r+HAUnDyFxqJr92UolsGswwim5
# 3j3YUa8mFyZu6GFQqnzlvHc98snkY4vcECQW6Q/favSvpf8hxBThCivhyFQOCpZ9
# cc+ewKBgvTuEFVqpLhm2ruppvTIr/j3XexpLhI3A4J9yGtNQOXp/spqj+nZPNXnO
# bXrQ50SGEkLcZL+x/8lItBtqz+6eRhoOAMFRdwozVGSJclkIJTLOXhY2go+KX2xm
# 28xm8Rg7mU+zmfMlDaIGtN/IBSjxsKhtPsDXtk8UVV08zszWbI805ADSexXmONFU
# eo2ECN8yM6WSV5S/H4cMKqShUjjfg58edY0ZvhFA/6Bpl6EdJMjbonphnvl/jywh
# XmjdMLWxaprHN5PU+FaLAEdfgdQdBMFUqSVB1xGJoQ84fQHhEMHOhPGIoYIYETCC
# GA0GCisGAQQBgjcDAwExghf9MIIX+QYJKoZIhvcNAQcCoIIX6jCCF+YCAQMxDzAN
# BglghkgBZQMEAgEFADCCAWIGCyqGSIb3DQEJEAEEoIIBUQSCAU0wggFJAgEBBgor
# BgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIJGUIjHpakwHH7rbkeVRd7ER04Sf
# 3483c8LKRz0rlrPjAgZpwnKumO4YEzIwMjYwMzMwMjIzNzM4LjU1NlowBIACAfSg
# geGkgd4wgdsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAj
# BgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5T
# aGllbGQgVFNTIEVTTjo3RDAwLTA1RTAtRDk0NzE1MDMGA1UEAxMsTWljcm9zb2Z0
# IFB1YmxpYyBSU0EgVGltZSBTdGFtcGluZyBBdXRob3JpdHmggg8hMIIHgjCCBWqg
# AwIBAgITMwAAAAXlzw//Zi7JhwAAAAAABTANBgkqhkiG9w0BAQwFADB3MQswCQYD
# VQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMUgwRgYDVQQD
# Ez9NaWNyb3NvZnQgSWRlbnRpdHkgVmVyaWZpY2F0aW9uIFJvb3QgQ2VydGlmaWNh
# dGUgQXV0aG9yaXR5IDIwMjAwHhcNMjAxMTE5MjAzMjMxWhcNMzUxMTE5MjA0MjMx
# WjBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0Eg
# MjAyMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJ5851Jj/eDFnwV9
# Y7UGIqMcHtfnlzPREwW9ZUZHd5HBXXBvf7KrQ5cMSqFSHGqg2/qJhYqOQxwuEQXG
# 8kB41wsDJP5d0zmLYKAY8Zxv3lYkuLDsfMuIEqvGYOPURAH+Ybl4SJEESnt0MbPE
# oKdNihwM5xGv0rGofJ1qOYSTNcc55EbBT7uq3wx3mXhtVmtcCEr5ZKTkKKE1CxZv
# NPWdGWJUPC6e4uRfWHIhZcgCsJ+sozf5EeH5KrlFnxpjKKTavwfFP6XaGZGWUG8T
# ZaiTogRoAlqcevbiqioUz1Yt4FRK53P6ovnUfANjIgM9JDdJ4e0qiDRm5sOTiEQt
# BLGd9Vhd1MadxoGcHrRCsS5rO9yhv2fjJHrmlQ0EIXmp4DhDBieKUGR+eZ4CNE3c
# tW4uvSDQVeSp9h1SaPV8UWEfyTxgGjOsRpeexIveR1MPTVf7gt8hY64XNPO6iyUG
# sEgt8c2PxF87E+CO7A28TpjNq5eLiiunhKbq0XbjkNoU5JhtYUrlmAbpxRjb9tSr
# eDdtACpm3rkpxp7AQndnI0Shu/fk1/rE3oWsDqMX3jjv40e8KN5YsJBnczyWB4Jy
# eeFMW3JBfdeAKhzohFe8U5w9WuvcP1E8cIxLoKSDzCCBOu0hWdjzKNu8Y5SwB1lt
# 5dQhABYyzR3dxEO/T1K/BVF3rV69AgMBAAGjggIbMIICFzAOBgNVHQ8BAf8EBAMC
# AYYwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFGtpKDo1L0hjQM972K9J6T7Z
# PdshMFQGA1UdIARNMEswSQYEVR0gADBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0l
# BAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDwYDVR0T
# AQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTIftJqhSobyhmYBAcnz1AQT2ioojCBhAYD
# VR0fBH0wezB5oHegdYZzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# cmwvTWljcm9zb2Z0JTIwSWRlbnRpdHklMjBWZXJpZmljYXRpb24lMjBSb290JTIw
# Q2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDIwLmNybDCBlAYIKwYBBQUHAQEE
# gYcwgYQwgYEGCCsGAQUFBzAChnVodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL2NlcnRzL01pY3Jvc29mdCUyMElkZW50aXR5JTIwVmVyaWZpY2F0aW9uJTIw
# Um9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAyMC5jcnQwDQYJKoZI
# hvcNAQEMBQADggIBAF+Idsd+bbVaFXXnTHho+k7h2ESZJRWluLE0Oa/pO+4ge/XE
# izXvhs0Y7+KVYyb4nHlugBesnFqBGEdC2IWmtKMyS1OWIviwpnK3aL5JedwzbeBF
# 7POyg6IGG/XhhJ3UqWeWTO+Czb1c2NP5zyEh89F72u9UIw+IfvM9lzDmc2O2END7
# MPnrcjWdQnrLn1Ntday7JSyrDvBdmgbNnCKNZPmhzoa8PccOiQljjTW6GePe5sGF
# uRHzdFt8y+bN2neF7Zu8hTO1I64XNGqst8S+w+RUdie8fXC1jKu3m9KGIqF4aldr
# YBamyh3g4nJPj/LR2CBaLyD+2BuGZCVmoNR/dSpRCxlot0i79dKOChmoONqbMI8m
# 04uLaEHAv4qwKHQ1vBzbV/nG89LDKbRSSvijmwJwxRxLLpMQ/u4xXxFfR4f/gksS
# kbJp7oqLwliDm/h+w0aJ/U5ccnYhYb7vPKNMN+SZDWycU5ODIRfyoGl59BsXR/Hp
# RGtiJquOYGmvA/pk5vC1lcnbeMrcWD/26ozePQ/TWfNXKBOmkFpvPE8CH+EeGGWz
# qTCjdAsno2jzTeNSxlx3glDGJgcdz5D/AAxw9Sdgq/+rY7jjgs7X6fqPTXPmaCAJ
# KVHAP19oEjJIBwD1LyHbaEgBxFCogYSOiUIr0Xqcr1nJfiWG2GwYe6ZoAF1bMIIH
# lzCCBX+gAwIBAgITMwAAAFXZ3WkmKPn44gAAAAAAVTANBgkqhkiG9w0BAQwFADBh
# MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIw
# MAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAy
# MDAeFw0yNTEwMjMyMDQ2NDlaFw0yNjEwMjIyMDQ2NDlaMIHbMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046N0QwMC0w
# NUUwLUQ5NDcxNTAzBgNVBAMTLE1pY3Jvc29mdCBQdWJsaWMgUlNBIFRpbWUgU3Rh
# bXBpbmcgQXV0aG9yaXR5MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# vbkfkh5ZSLP0MCUWafaw/KZoVZu9iQx8r5JwhZvdrUi86UjCCFQONjQanrIxGF9h
# RGIZLQZ50gHrLC+4fpUEJff5t04VwByWC2/bWOuk6NmaTh9JpPZDcGzNR95Qlryj
# fEjtl+gxj12zNPEdADPplVfzt8cYRWFBx/Fbfch08k6P9p7jX2q1jFPbUxWYJ+xO
# yGC1aKhDGY5b+8wL39v6qC0HFIx/v3y+bep+aEXooK8VoeWK+szfaFjXo8YTcvQ8
# UL4szu9HFTuZNv6vvoJ7Ju+o5aTj51sph+0+FXW38TlL/rDBd5ia79jskLtOeHbD
# jkbljilwzegcxv9i49F05ZrS/5ELZCCY1VaqO7EOLKVaxxdAO5oy1vb0Bx0ZRVX1
# mxFjYzay2EC051k6yGJHm58y1oe2IKRa/SM1+BTGse6vHNi5Q2d5ZnoR9AOAUDDw
# JIIqRI4rZz2MSinh11WrXTG9urF2uoyd5Ve+8hxes9ABeP2PYQKlXYTAxvdaeanD
# TQ/vwmnM+yTcWzrVm84Z38XVFw4G7p/ZNZ2nscvv6uru2AevXcyV1t8ha7iWmhhg
# TWBNBrViuDlc3iPvOz2SVPbPeqhyY/NXwNZCAgc2H5pOztu6MwQxDIjte3XM/FkK
# BxHofS2abNT/0HG+xZtFqUJDaxgbJa6lN1zh7spjuQ8CAwEAAaOCAcswggHHMB0G
# A1UdDgQWBBRWBF8QbdwIA/DIv6nJFsrB16xltjAfBgNVHSMEGDAWgBRraSg6NS9I
# Y0DPe9ivSek+2T3bITBsBgNVHR8EZTBjMGGgX6BdhltodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBQdWJsaWMlMjBSU0ElMjBU
# aW1lc3RhbXBpbmclMjBDQSUyMDIwMjAuY3JsMHkGCCsGAQUFBwEBBG0wazBpBggr
# BgEFBQcwAoZdaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9N
# aWNyb3NvZnQlMjBQdWJsaWMlMjBSU0ElMjBUaW1lc3RhbXBpbmclMjBDQSUyMDIw
# MjAuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYD
# VR0PAQH/BAQDAgeAMGYGA1UdIARfMF0wUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYB
# BQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBv
# c2l0b3J5Lmh0bTAIBgZngQwBBAIwDQYJKoZIhvcNAQEMBQADggIBAFIe4ZJUe9qU
# KcWeWypchB58fXE/ZIWv2D5XP5/k/tB7LCN9BvmNSVKZ3VeclQM978wfEvuvdMQS
# Uv6Y20boIM8DK1K1IU9cP21MG0ExiHxaqjrikf2qbfrXIip4Ef3v2bNYKQxCxN3S
# czp1SX0H7uqK2L5OhfDEiXf15iou5hh+EPaaqp49czNQpJDOR/vfJghUc/qcslDP
# hoCZpZx8b2ODvywGQNXwqlbsmCS24uGmEkQ3UH5JUeN6c91yasVchS78riMrm6R9
# ZpAiO5pfNKMGU2MLm1A3pp098DcbFTAc95Hh6Qvkh//28F/Xe2bMFb6DL7Sw0ZO9
# 5v0gv0ZTyJfxS/LCxfraeEII9FSFOKAMEp1zNFSs2ue0GGjBt9yEEMUwvxq9ExFz
# 0aZzYm8ivJfffpIVDnX/+rVRTYcxIkQyFYslIhYlWF9SjCw5r49qakjMRNh8W9O7
# aaoolSVZleQZjGt0K8JzMlyp6hp2lbW6XqRx2cOHbbxJDxmENzohGUziI13lI2g2
# Bf5qibfC4bKNRpJo9lbE8HUbY0qJiE8u3SU8eDQaySPXOEhJjxRCQwwOvejYmBG5
# P7CckQNBSnnl12+FKRKgPoj0Mv+z5OMhj9z2MtpbnHLAkep0odQClEyyCG/uR5tK
# 5rW6mZH5Oq56UWS0NI6NV1JGS7Jri6jFMYIHQzCCBz8CAQEweDBhMQswCQYDVQQG
# EwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylN
# aWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMAITMwAAAFXZ
# 3WkmKPn44gAAAAAAVTANBglghkgBZQMEAgEFAKCCBJwwEQYLKoZIhvcNAQkQAg8x
# AgUAMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcN
# MjYwMzMwMjIzNzM4WjAvBgkqhkiG9w0BCQQxIgQgWiAGjQ9Z9fgYDCmYNRb4a4eb
# 7BCvWpNoKuj73gTBW7AwgbkGCyqGSIb3DQEJEAIvMYGpMIGmMIGjMIGgBCDYuTyX
# ZIZiu799/v4PaqsmeSzBxh0rqkYq7sYYavj+zTB8MGWkYzBhMQswCQYDVQQGEwJV
# UzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNy
# b3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMAITMwAAAFXZ3Wkm
# KPn44gAAAAAAVTCCA14GCyqGSIb3DQEJEAISMYIDTTCCA0mhggNFMIIDQTCCAikC
# AQEwggEJoYHhpIHeMIHbMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYD
# VQQLEx5uU2hpZWxkIFRTUyBFU046N0QwMC0wNUUwLUQ5NDcxNTAzBgNVBAMTLE1p
# Y3Jvc29mdCBQdWJsaWMgUlNBIFRpbWUgU3RhbXBpbmcgQXV0aG9yaXR5oiMKAQEw
# BwYFKw4DAhoDFQAdO1QBgmW/tuBZV5EGjhfsV4cN6qBnMGWkYzBhMQswCQYDVQQG
# EwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylN
# aWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMDANBgkqhkiG
# 9w0BAQsFAAIFAO102h0wIhgPMjAyNjAzMzAxMTE2NDVaGA8yMDI2MDMzMTExMTY0
# NVowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA7XTaHQIBADAHAgEAAgIIIzAHAgEA
# AgISvDAKAgUA7XYrnQIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBCwUAA4IBAQAK877s
# agl4GbNJbhHNZdXMFJLS6U8vywIt668EFo2xxl8FYVZ2sT+1OUL0UHZzSHbchC+D
# ciOmqJert7xuM7t10gbLULkjwx4GCrwWoLpLRMGQwO7d7OLFJcbM27VGDgpt9ySn
# oVNE506gPe05jlfoyhqL3f1EztzmVUDDa5QOkRxCZpEUbvq40aRKBr/B69HzEawO
# L0/uWGTC/oEv3s8vZLM/zM0sAeKWzedzF7Z4oDpBnoWOyjvk5F2XdkEo4CUba/G/
# sL5Fiml5M0xCcKPcDYD99txMBETKpp9j0811Ja08BgFVgMWAjli0k4wFqjk6r2Jb
# e4d6W2EWeLvfq0V8MA0GCSqGSIb3DQEBAQUABIICAEOAFf5lFKKgrg754jjvno8U
# zLqjc1oK58M/R1czyQf/UiyTECzib4sjOnd0DxCg18ZNyGtKSVfu29jRbNGZM8Zm
# TWVzatdS5hhySiTa4ZC8djxPofmDS4e7W0BeL/enDP00HOEzIbJtTJzQej4QqwzY
# pWBOlwfWP3sblQTp+BfHQpn1/yCaVs29h8cfwD8+u7Fp2VShVEsqoIfZaYKBObbr
# FwFU2CGERx1ckSrVF8MMQILQKsDYIje5x2Oh+guY4cVUFSCF/WLUoaoi/ljjAeiE
# ovRUdvz+86t9jwP0zxFxBPHV9Eu8bgH/bOr3pYh0tRHjtAxlQ/sMggH91Qnh7q+/
# YgGbZdSkVUw9oMHLCeI9thESTai6srxO2KT8SJxeRguoohiqciXbVU1fC0zzOLkA
# n+RDKCP2sP2EVttfftkrGy/Vv1KIHvBypp9G7r0Jf/wnzmrtcNTxI64vJQLg14MY
# fE151dVj6R9Vel0r6ey8y0V8tS566YHsWZkmUp4JD1rYtir1ka6aAW4m6NPPWSGo
# EO7Ilub0z3Gr1U0yJe7NHVylfIysDoZ2sCiY0oPjs+zRu6ecaKnvBI9shxoEAggP
# 6CMy4cyXUPY0BMH6LlXhLyY7FvCVTMQvXcpnmo1BDMpKlf45ruOaRvOAmlP8yfdk
# aNzb2LkjCMA7qZjvO0CG
# SIG # End signature block
