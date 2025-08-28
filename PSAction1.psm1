# Name: PSAction1
# Description: Powershell module for working with the Aciton1 API.
# Copyright (C) 2024 Action1 Corporation
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
$script:Action1_Hosts = [ordered]@{'North America' = 'https://app.action1.com/api/3.0'; Europe = 'https://app.eu.action1.com/api/3.0'; Australia = 'https://app.au.action1.com/api/3.0' }
$Script:Action1_BaseURI = ''
$Script:Action1_Default_Org
$Script:Action1_DebugEnabled = $false
$Script:Action1_Interactive = $false
$Script:Action1_CVE_Lookup = @{}

$URILookUp = @{
    G_AdvancedSettings     = { param($Org_ID) "/setting_templates/$Org_ID" }
    G_AgentDepoyment       = { param($Org_ID) "/endpoints/discovery/$Org_ID" }
    G_Apps                 = { param($Org_ID) "/apps/$Org_ID/data" }
    G_AutomationInstances  = { param($Org_ID, $Object_ID) "/automations/instances/$Org_ID`?limit=9999&from=0&endpoint_id=$Object_ID" }
    G_Automations          = { param($Org_ID) "/policies/schedules/$Org_ID" }
    G_Endpoint             = { param($Org_ID, $Object_ID) "/endpoints/managed/$Org_ID/$Object_ID" }
    G_Endpoints            = { param($Org_ID) "/endpoints/managed/$Org_ID" }
    G_EndpointApps         = { param($Org_ID, $Object_ID) "/apps/$Org_ID/data/$Object_ID" }
    G_EndpointGroupMembers = { param($Org_ID, $Object_ID)"/endpoints/groups/$Org_ID/$Object_ID/contents" }
    G_EndpointGroups       = { param($Org_ID) "/endpoints/groups/$Org_ID" }
    G_Logs                 = { param($Org_ID) "/logs/$Org_ID" }
    G_Me                   = { "/Me" }
    G_MissingUpdates       = { param($Org_ID) "/updates/$Org_ID`?limit=9999" }
    G_Organizations        = { "/organizations" }
    G_Package              = { param($Org_ID, $Object_ID) "/software-repository/$Org_ID/$Object_ID" }
    G_Packages             = { "/packages/all?limit=9999" }
    G_PackageVersions      = { param($Object_ID) "/software-repository/all/$Object_ID`?fields=versions" }
    G_SoftwareRepository   = { param($Org_ID) "/software-repository/$Org_ID" }
    G_Versions             = { param($Org_ID, $Object_ID) "/software-repository/$Org_ID/$Object_ID`?fields=versions" }
    G_Version              = { param($Org_ID, $Package_ID, $Object_ID) "/software-repository/$Org_ID/$Package_ID/versions/$Object_ID" }
    G_Policy               = { param($Org_ID, $Object_ID) "/policies/instances/$Org_ID/$Object_ID" }
    G_Policies             = { param($Org_ID)  "/policies/instances/$Org_ID" }
    G_PolicyResults        = { param($Org_ID, $Object_ID) "/policies/instances/$Org_ID/$Object_ID/endpoint_results" }
    G_ReportData           = { param($Org_ID, $Object_ID)"/reportdata/$Org_ID/$Object_ID/data" }
    G_ReportExport         = { param($Org_ID, $Object_ID)"/reportdata/$Org_ID/$Object_ID/export" }
    G_Reports              = { "/reports/all" } 
    G_Scripts              = { param($Org_ID) "/scripts/$Org_ID" } 
    G_Vulnerabilities      = { param($Org_ID) "/Vulnerabilities/$Org_ID`?limit=9999" }
    N_Automation           = { param($Org_ID)  "/policies/schedules/$Org_ID" }
    N_EndpointGroup        = { param($Org_ID) "/endpoints/groups/$Org_ID" }
    N_Organization         = { "/organizations" }
    N_Remediation          = { param($Org_ID)  "/policies/instances/$Org_ID" }
    N_DeferredRemediation  = { param($Org_ID)  "/policies/schedules/$Org_ID" }
    N_DeploySoftware       = { param($Org_ID)  "/policies/instances/$Org_ID" }
    N_Package              = { param($Org_ID) "/software-repository/$Org_ID" }
    N_Version              = { param($Org_ID, $Object_ID) "/software-repository/$Org_ID/$Object_ID/versions" }
    R_ReportData           = { param($Org_ID, $Object_ID) "/reportdata/$Org_ID/$Object_ID/requery" }
    R_InstalledSoftware    = { param($Org_ID, $Object_ID) "/apps/$Org_ID/requery/$Object_ID" }
    R_InstalledUpdates     = { param($Org_ID) "/updates/installed/$Org_ID/requery" }
    U_Endpoint             = { param($Org_ID, $Object_ID) "/endpoints/managed/$Org_ID/$Object_ID" }
    U_GroupModify          = { param($Org_ID, $Object_ID) "/endpoints/groups/$Org_ID/$Object_ID" }
    U_GroupMembers         = { param($Org_ID, $Object_ID) "/endpoints/groups/$Org_ID/$Object_ID/contents" }
    U_Package              = { param($Org_ID, $Object_ID) "/software-repository/$Org_ID/$Object_ID" }
    U_Version              = { param($Org_ID, $Package_ID, $Object_ID) "/software-repository/$Org_ID/$Package_ID/versions/$Object_ID" }
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
            return (Invoke-WebRequest -Uri $Path -Method GET -UseBasicParsing -Headers @{Authorization = "Bearer $(($Script:Action1_Token).access_token)"; 'Content-Type' = 'application/json' }).Content
        }
        else { 
            return (ConvertFrom-Json -InputObject (Invoke-WebRequest -Uri $Path -Method GET -UseBasicParsing -Headers @{Authorization = "Bearer $(($Script:Action1_Token).access_token)"; 'Content-Type' = 'application/json' }).Content ) 
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
            'Windows_64',
            'Windows_ARM64',
            'Mac_IntelCPU',
            'Mac_AppleSilicon'
        )]
        [String]$Platform,
        [int32]$BufferSize = 24Mb,
        [String]$Org_ID = $Script:Action1_Default_Org
    )
    $uri = "$Script:Action1_BaseURI/software-repository/$Org_ID/$Package_ID/versions/$Version_ID/upload?platform=$Platform" 
    Debug-Host "Base URI is $uri"
    $UploadTarget = ""
    Debug-Host "Uploading file: '$Filename'"
    Debug-Host "Writing in chunks of $BufferSize bytes."
    $FileData = [System.IO.File]::Open($Filename, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
    if ($FileData.Length -lt $BufferSize) {
        $BufferSize = $FileData.Length
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
        $Headers.Add('Content-Type', 'application/json')
        if (CheckToken) { 
            $Headers.Add('Authorization', "Bearer $(($Script:Action1_Token).access_token)")
            Invoke-WebRequest -Uri $uri -Method Post -UseBasicParsing -Headers $Headers -ErrorAction SilentlyContinue 
        }
    }
    catch { 
        try {
            $UploadTarget = $_.Exception.Response.Headers.GetValues('X-Upload-Location')[0]
        }
        catch {
           Write-Error "Error starting upload: $($_.Exception.Message)"
           return $null
        }
    } 
    Debug-Host "Upload URI is $UploadTarget"
   
    while (($Read = $FileData.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
        $Headers = $HeaderBase.Clone()
        $Headers.Add('Content-Range', "bytes $($Place)-$($($Place + $Read-1))/$($FileData.Length)")
        $Headers.Add('Content-Length', "$($Read)")
        $Headers.Add('Content-Type', 'application/octet-stream')
        $Place += $Read
        try { 
            Debug-Host "Starting Upload of $($Buffer.Length) bytes at position $Place."
            if (CheckToken) {
                    $Headers.Add('Authorization', "Bearer $(($Script:Action1_Token).access_token)")
                    $response = Invoke-WebRequest -Method Put -UseBasicParsing -Uri $UploadTarget -Body $Buffer -Headers $Headers -ErrorAction SilentlyContinue 
                } 
            }
        catch { 
            Debug-Host "Last Status: $($_.Exception.Response.StatusCode)" 
            if ($_.Exception.Response.StatusCode.value -eq 403) {
                Debug-Host "Access denied. Requires permission: manage_software_repository."
                return $null
            }
            if ($_.Exception.Response.StatusCode.value -eq 500) {
                Debug-Host "Internal server error, attempting to continue upload."
                [scriptblock] $ScriptBlock = {
                    $resumePoint = Resume-Action1PackageUpload -Package_ID $Package_ID -Version_ID $Version_ID -Filename $Filename -Platform $Platform -UploadTarget $UploadTarget.Split('=')[2] -BufferSize $BufferSize -Org_ID $Org_ID
                    return $resumePoint
                }
                try {
                    $Place = Invoke-WithRetries -ScriptBlock $ScriptBlock -MaxNumberOfAttempts 5 -MillisecondsToWaitBetweenAttempts 3000 -ExponentialBackoff $true
                    Debug-Host "Setting position of filestream to byte $Place and resuming upload."
                    $FileData.Seek($Place, [System.IO.SeekOrigin]::Begin) |  Out-Null
                }
                catch {
                    throw "Failed to resume upload after multiple attempts."
                }
            }
        }

        if (($FileData.Length - $Place) -lt $BufferSize) { 
            $buffer = New-Object byte[] ($FileData.Length - $place) 
            Debug-Host "Remaining size is smaller than buffer size, adjusting to $($FileData.Length - $Place)"
        }

        Debug-Host "Upload $([math]::Round((($Place / $FileData.Length)*100),1))% Complete."

        if ($Buffer.Length -eq 0) { 
            Debug-Host "Final Status:$($response.StatusCode)"
            if ($response.StatusCode -eq 200) {
                Debug-Host "Upload completed successfully."
                $file = Split-Path $Filename -leaf
                $updatedVersion = Get-Action1 -Query Version -Id $Version_ID -Id2 $Package_ID
                if($updatedVersion.file_name.PSobject.Properties.Name -contains $Platform){
                    $updatedVersion.file_name.$Platform.name = $file
                    $updatedVersion.file_name.$Platform.type = 'cloud'
                }
                else{
                    Add-Member -InputObject $updatedVersion.file_name -TypeName NoteProperty -MemberType NoteProperty -Name $Platform -Value @{
                        name = $file
                        type = 'cloud'
                    }
                }
                If($null -ne (Update-Action1 -Type Version -Action Modify -Data $updatedVersion -Id $Version_ID -Id2 $Package_ID)) {
                    Debug-Host "Package version $Version_ID updated successfully to reference uploaded file $file."
                } 
                else {
                    Write-Error "Error updating package version $Version_ID to reference uploaded file $file." 
                }
            }
        }
        else { 
            Debug-Host "Bytes Written: $($Buffer.Length)"
        }
    }
    $FileData.Close()
}

function Resume-Action1PackageUpload {
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
            'Windows_64',
            'Windows_ARM64',
            'Mac_IntelCPU',
            'Mac_AppleSilicon'
        )]
        [String]$Platform,
        [Parameter(Mandatory)]
        [int32]$UploadTarget,
        [int32]$BufferSize = 24Mb,
        [String]$Org_ID = $Script:Action1_Default_Org
    )
    if (CheckToken) {
        $Headers = $HeaderBase.Clone()
        $Headers.Add('Content-Range', "bytes */$($FileData.Length)")
        $Headers.Add('Content-Length', "0")
        $Headers.Add('Content-Type', 'application/octet-stream')
        $uri = "$Script:Action1_BaseURI/software-repository/$Org_ID/$Package_ID/versions/$Version_ID/upload?platform=$Platform&upload_id=$UploadTarget"
        Debug-Host "Querying server for resume point of: '$Filename'upload."
        try {
            if (CheckToken) {
                $response = Invoke-WebRequest -Uri $uri -Method Put -UseBasicParsing -Headers $Headers -ErrorAction SilentlyContinue 
            }
        }
        catch {
            if ($response.StatusCode -eq 308) {
                Debug-Host "Resume point found, continuing upload."
                return $response.Headers['Range'].Split('-')[1] -as [int]
            }
            elseif($response.StatusCode -eq 500) {
                Debug-Host "Internal server error, attempting to continue upload."
                throw
            }
            else {
                Debug-Host "Error resuming upload: $($_.Exception.Message)"
                throw
            }
        }
    }
}
function Invoke-WithRetries {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory)]
    [ValidateNotNull()]
    [scriptblock] $ScriptBlock,

    [ValidateRange(1, [int]::MaxValue)]
    [int] $MaxNumberOfAttempts = 5,

    [ValidateRange(1, [int]::MaxValue)]
    [int] $MillisecondsToWaitBetweenAttempts = 3000,

    [ValidateRange(1, [int]::MaxValue)]
    [int] $MaxMillisecondsToWait = 300000,

    [bool] $ExponentialBackoff = $false

  )

  [int] $numberOfAttempts = 0
  while ($true) {
    try {
      Invoke-Command -ScriptBlock $ScriptBlock
      break 
    } 
    catch {
      $numberOfAttempts++

      [string] $errorMessage = $_.Exception.ToString()
      [string] $errorDetails = $_.ErrorDetails
      Debug-Host "Attempt number '$numberOfAttempts' of '$MaxNumberOfAttempts' failed.`nError: $errorMessage `nErrorDetails: $errorDetails"
      if ($numberOfAttempts -ge $MaxNumberOfAttempts) {
        throw
    }
      [int] $millisecondsToWait = $MillisecondsToWaitBetweenAttempts
      if ($ExponentialBackoff) {
        # Calculate exponential backoff time capped at MaxMillisecondsToWait
        $millisecondsToWait = [System.Math]::Floor($MillisecondsToWaitBetweenAttempts * $numberOfAttempts,$MaxMillisecondsToWait)
      }
      Debug-Host "Waiting '$millisecondsToWait' milliseconds before next attempt."
      Start-Sleep -Milliseconds $millisecondsToWait
    }
  }
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
        return (ConvertFrom-Json -InputObject (Invoke-WebRequest -Uri $Path -Method $Method -UseBasicParsing -Body (ConvertTo-Json -InputObject $Body -Depth 10) -Headers @{Authorization = "Bearer $(($Script:Action1_Token).access_token)"; 'Content-Type' = 'application/json' }).Content)
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
    param (
        [Parameter(Mandatory)]
        [ValidateSet('NorthAmerica', 'Europe')]
        [String]$Region
    )
    Write-Host "Locale set, Note:Set-Action1Locale is being depreciated, please modify all scripts to use Set-Action1Region instead." -ForegroundColor Red
    Set-Action1Region -Region $Region
}

function Set-Action1Region {
    param (
        [Parameter(Mandatory)]
        [ValidateSet('NorthAmerica', 'Europe', 'Australia')]
        [String]$Region
    )
    switch ($Region) {
        NorthAmerica { $Script:Action1_BaseURI = "https://app.action1.com/api/3.0" }
        Europe { $Script:Action1_BaseURI = "https://app.eu.action1.com/api/3.0" }
        Australia { $Script:Action1_BaseURI = 'https://app.au.action1.com/api/3.0' }
    }
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
            'CutomAttribute',
            'EndpointGroupMembers',
            'EndpointGroups',
            'Me',
            'Endpoint',
            'EndpointApps',
            'Endpoints',
            'Logs',
            'MissingUpdates',
            'Organizations',
            'Package',
            'Packages',
            'PackageVersions',
            'SoftwareRepository',
            'Versions',
            'Version',
            'Policy',
            'Policies',
            'PolicyResults',
            'ReportData',
            'ReportExport',
            'Reports',
            'Scripts',
            'AgentDepoyment',
            'Vulnerabilities',
            'RawURI',
            'Settings'
        )]
        [String]$Query,
        [string]$Id,
        [string]$Id2, #Secondary ID for nested objects such as versions under packages.
        #[int]$Limit,
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
    if ($Query -eq 'RawURI') { if (!$URI) { Write-Error "Error -URI value required when Query is type URI.`n"; return $null }else { if (CheckToken) { return DoGet -Path $URI -Label $Query } } }
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

        if ($Limit -gt 0) { $AddArgs = BuildArgs -In $AddArgs -Add "limit=$Limit" }
        if ($From -gt 0) { $AddArgs = BuildArgs -In $AddArgs -Add "from=$From" }
        #Add more URI arguments here?..
        $arglist = @{}
        switch -Regex ($URILookUp["G_$Query"].ToString()) {
            '\$Package_ID' {
                $arglist['Package_ID'] = $Id2;
            }
            '\$Org_ID' {
                $arglist['Org_ID'] = $(CheckOrg)
            }
            '\$Object_ID' {
                $arglist['Object_ID'] = $Id
            }
        }
        $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["G_$Query"] @arglist)

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
                'Versions' {
                    Write-Output $page.versions
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
            'Package',
            'Version'
        )]
        [string]$Item,
        [Parameter(Mandatory)]
        [object]$Data,
        [string]$Object_ID                 
    )
    Debug-Host "Creating new $Item."
    if (CheckToken) {
        try {
            if (!$URILookUp["N_$Item"].ToString().Contains("`$Org_ID")) {
                $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["N_$Item"])
            }
            elseif(!$URILookUp["N_$Item"].ToString().Contains("`$Object_ID")) {
                $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["N_$Item"] -Org_ID $(CheckOrg))
            }
            else {
                $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["N_$Item"] -Org_ID $(CheckOrg) -Object_ID $Object_ID)
            } 
            switch ($Item) {
                'Version' {
                    $Data.PSObject.Members | ForEach-Object { if (@('id','type','self','binary_id','scoped_approvals') -contains $_.Name) { $Data.PSObject.Members.Remove($_.Name) } }
                }
                'Package' {
                    $Data.PSObject.Members | ForEach-Object { if (@('id','type','self','builtin','organization_id','platform','update_type','scope') -contains $_.Name) { $Data.PSObject.Members.Remove($_.Name) } }
                }
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
            'Package',
            'Version'
        )]
        [string]$Type,
        [object]$Data,
        [string]$Id,
        [string]$Id2,  #Used for version updates where package ID is also required. TODO: change to hashtable?
        [string]$AttributeName,
        [string]$AttributeValue,
        [switch]$Force
    )
    Debug-Host "Trying update for $Action => $Type."
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
                        $Data = New-Object psobject -Property @{"custom:$AttributeName" = $AttributeValue; }
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
                    'Package' {
                        $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["U_Package"] -Org_ID $(CheckOrg) -Object_Id $Id)
                        $Data.PSObject.Members | ForEach-Object { if (@('id','type','self','builtin','organization_id','platform','update_type','scope') -contains $_.Name) { $Data.PSObject.Members.Remove($_.Name) } }
                        return PushData -Method PATCH -Path $Path -Body $Data -Label "$Action=>$Type" 
                    }
                    'Version' {
                        $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["U_Version"] -Org_ID $(CheckOrg) -Object_Id $Id -Package_ID $Id2) 
                        $Data.PSObject.Members | ForEach-Object { if (@('id','type','self','binary_id','scoped_approvals') -contains $_.Name) { $Data.PSObject.Members.Remove($_.Name) } }
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
                    'Package' {
                        if ($force -or ((Read-Host "Are you sure you want to $Action $Type [$id]?`n[Y]es to confirm, any other key to cancel.") -eq 'Y')) {
                            $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["U_Package"] -Org_ID $(CheckOrg) -Object_Id $Id)
                            return PushData -Method DELETE -Path $Path -Label "$Action=>$Type"
                        }
                    }
                    'Version' {
                        if ($force -or ((Read-Host "Are you sure you want to $Action $Type [$id]?`n[Y]es to confirm, any other key to cancel.") -eq 'Y')) {
                            $Path = "$Script:Action1_BaseURI{0}" -f (& $URILookUp["U_Version"] -Org_ID $(CheckOrg) -Object_Id $Id -Package_ID $Id2) 
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


