# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

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
    if (!$Script:Action1_UriMap["R_$Type"].ToString().Contains("`$Org_ID")) {
        $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap["R_$Type"])
    }
    else {
        if ($Endpoint_Id) {
            if ($Script:Action1_UriMap["R_$Type"].ToString().Contains("`$Object_ID")) {
                $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap["R_$Type"] -Org_ID $(Initialize-Action1DefaultOrg) -Object_ID $Endpoint_Id)
            }
            else {
                Write-Error "Endpoint_Id was specified but this action is not endpoint specific, can continue, defaulting to system wide."
                $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap["R_$Type"] -Org_ID $(Initialize-Action1DefaultOrg))
            } 
        }
        else {
            $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap["R_$Type"] -Org_ID $(Initialize-Action1DefaultOrg))
        }
    } 

    return Invoke-Action1ApiRequest -Method POST -Path $Path.TrimEnd('/') -Label "Requery=>$Type"  
}
