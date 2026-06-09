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
    Write-Action1Debug "Trying update for $Action => $Type."
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
                    $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap["U_GroupMembers"] -Org_ID $(Initialize-Action1DefaultOrg) -Object_ID $id)
                    return Invoke-Action1ApiRequest -Method POST -Path $Path -Body $Data -Label "$Action=>$Type"
                }
                default { Write-Error "Invalid request of $Type for query $Action." ; return $null }
            }
        }
        'Modify' {              
            if (!$Id) { Write-Error "When perfoming $Action=>$Type, the value for -Id must be specified to know what object to act on."; return $null } 
            switch ($Type) {
                'Automation' {
                    $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap["U_Automation"] -Org_ID $(Initialize-Action1DefaultOrg) -Object_Id $Id)
                    return Invoke-Action1ApiRequest -Method PATCH -Path $Path -Body $Data -Label "$Action=>$Type" 
                }
                'CustomAttribute' {
                    $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap["U_Endpoint"] -Org_ID $(Initialize-Action1DefaultOrg) -Object_Id $Id)
                    $Data = New-Object psobject -Property @{"custom:$AttributeName" = $AttributeValue }
                    return Invoke-Action1ApiRequest -Method PATCH -Path $Path -Body $Data -Label "$Action=>$Type" 
                }
                'Endpoint' { 
                    $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap["U_Endpoint"] -Org_ID $(Initialize-Action1DefaultOrg) -Object_Id $Id)
                    $Data.PSObject.Members | ForEach-Object { if (@('name', 'comment') -notcontains $_.Name) { $Data.PSObject.Members.Remove($_.Name) } }
                    return Invoke-Action1ApiRequest -Method PATCH -Path $Path -Body $Data -Label "$Action=>$Type" 
                }
                'EndpointGroup' { 
                    $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap["U_GroupModify"] -Org_ID $(Initialize-Action1DefaultOrg) -Object_Id $Id)
                    return Invoke-Action1ApiRequest -Method PATCH -Path $Path -Body $Data -Label "$Action=>$Type"
                }
                default { Write-Error "Invalid request of $Type for query $Action." ; return $null }
            }   
        }
        'Delete' {
            Write-Action1Debug "Force delete enabled:$Force."
            switch ($Type) {
                'EndpointGroup' { 
                    if ($force -or ((Read-Host "Are you sure you want to $Action $Type [$id]?`n[Y]es to confirm, any other key to cancel.") -eq 'Y')) {
                        $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap["U_GroupModify"] -Org_ID $(Initialize-Action1DefaultOrg) -Object_Id $Id)
                        return Invoke-Action1ApiRequest -Method DELETE -Path $Path -Label "$Action=>$Type"
                    }
                }
                'Endpoint' { 
                    if ($force -or ((Read-Host "Are you sure you want to $Action $Type [$id]?`n[Y]es to confirm, any other key to cancel.") -eq 'Y')) {
                        $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap["U_Endpoint"] -Org_ID $(Initialize-Action1DefaultOrg) -Object_Id $Id)
                        return Invoke-Action1ApiRequest -Method DELETE -Path $Path -Label "$Action=>$Type"
                    }
                }
                'Automation' {
                    if ($force -or ((Read-Host "Are you sure you want to $Action $Type [$id]?`n[Y]es to confirm, any other key to cancel.") -eq 'Y')) {
                        $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap["U_Automation"] -Org_ID $(Initialize-Action1DefaultOrg) -Object_Id $Id)
                        return Invoke-Action1ApiRequest -Method DELETE -Path $Path -Label "$Action=>$Type"
                    }
                }
                default { Write-Error "Invalid request of $Type for query $Action." ; return $null }
            }
        }
        default { Write-Error "Invalid request of $Type for query $Action." ; return $null }
    }
}