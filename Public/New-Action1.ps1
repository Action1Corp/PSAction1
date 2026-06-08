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
        Write-Action1Debug "Creating new $Item."
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