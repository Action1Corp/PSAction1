# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

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
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Limit = 0,
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
                if ($Query -ne 'Settings') { Write-Error "Clone flag only allowed for query type 'Settings.'`n"; return $null }
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
                    default { Write-Error "Invalid request to clone type $For." ; return $null }
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
                        
                        $deploy = ConvertFrom-Json $Script:Action1_RemediationTemplate
                        $deploy.name = "E$tempxternal $For template $((Get-Date).ToString('yyyyMMddhhmmss'))"
                        $deploy.actions[0].params.display_summary = "$For via external API call."
                        $sbRefreshCVEList = {
                            $Script:Action1_CVE_Lookup = @{}
                            Write-Action1Debug "Refreshing CVE list at $(Get-Date)"
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
                                        Write-Action1Debug "$upd has already been added to this template.`nThis happens when an update addresses more than one CVE in a single package."
                                    }
                                    else {
                                        Write-Action1Debug "Adding $upd to the package list for $CVE_ID."
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
                        $deploy = ConvertFrom-Json $Script:Action1_PackageDeployTemplate
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
                                    Write-Action1Debug "$name has already been added to this template."
                                }
                                else {
                                    $version = $(Get-Action1 RawURI -URI "$Script:Action1_BaseURI/packages/all/$Package_ID/versions").version
                                    Write-Action1Debug "Adding $name version $Version to the package list."
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
        Invoke-Action1PagedGetRequest -Path $this.details -Label 'PolicyResultsDetails'
    }
    $sbCustomFieldGet = { param([string]$name)($this.custom | Where-Object { $_.name -eq $name }).value }

    $ItemAction = $null

    switch -Wildcard ($Query) {
        'PolicyResults' {
            $ItemAction = {
                param($Item)

                $Item | Add-Member -MemberType ScriptMethod -Name "GetDetails" -Value $sbPolicyResultsDetail -Force
                $Item
            }
        }

        'Endpoint*' {
            $ItemAction = {
                param($Item)

                $Item | Add-Member -MemberType ScriptMethod -Name "GetCustomAttribute" -Value $sbCustomFieldGet -Force
                $Item
            }
        }
    }

    if (!$Script:Action1_UriMap["G_$Query"].ToString().Contains("`$Org_ID")) {
        if (!$Script:Action1_UriMap["G_$Query"].ToString().Contains("`$Object_ID")) {
            $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap["G_$Query"])
        }
        else {
            if ($Id) {
                $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap["G_$Query"] -Object_ID $Id)
            }
            else {
                Write-Error 'This options requires that you specify an Object_ID.'
            }
        }
    }
    else {
        if ($Id) {
            $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap["G_$Query"] -Org_ID $(Initialize-Action1DefaultOrg) -Object_ID $Id)
        }
        else {
            $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap["G_$Query"] -Org_ID $(Initialize-Action1DefaultOrg))
        }
    }

    if ($Rawlist.Contains($Query)) {
        Invoke-Action1ApiRequest -Method GET -Path $Path -Label $Label -AddArgs $RequestArgs -RawResponse
        return
    }

    $PagedRequestArgs = @{
        Path    = $Path
        Label   = $Query
        AddArgs = $AddArgs
        Limit   = if ($Limit -gt 0) { $Limit } else { 200 }
    }

    switch -Wildcard ($Query) {
        'PolicyResults' {
            Invoke-Action1PagedGetRequest @PagedRequestArgs | Add-Action1PolicyResultDetailsMethod
            return
        }

        'Endpoint*' {
            Invoke-Action1PagedGetRequest @PagedRequestArgs | Add-Action1EndpointCustomAttributeMethod
            return
        }

        default {
            Invoke-Action1PagedGetRequest @PagedRequestArgs
            return
        }
    }                
}