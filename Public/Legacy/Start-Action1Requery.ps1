# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

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
    $uriPathBuilder = Get-UriMapValue -Key "R_$Type"
    $uriParameterNames = @(
        Get-Action1UriMapParameters -UriPathBuilder $uriPathBuilder
    )

    if ($uriParameterNames -notcontains 'OrgId') {
        $Path = "$Script:Action1_BaseURI{0}" -f (& $uriPathBuilder)
    }
    else {
        if (Initialize-Action1DefaultOrg) {
            $orgId = Get-Action1DefaultOrgId
        }

        if ($Endpoint_Id) {
            if ($uriParameterNames -contains 'ObjectId') {
                $Path = "$Script:Action1_BaseURI{0}" -f (& $uriPathBuilder -OrgId $orgId -ObjectId $Endpoint_Id)
            }
            else {
                Write-Error "Endpoint_Id was specified but this action is not endpoint specific, can continue, defaulting to system wide."
                $Path = "$Script:Action1_BaseURI{0}" -f (& $uriPathBuilder -OrgId $orgId)
            } 
        }
        else {
            $Path = "$Script:Action1_BaseURI{0}" -f (& $uriPathBuilder -OrgId $orgId)
        }
    } 

    return Invoke-Action1ApiRequest -Method POST -Path $Path.TrimEnd('/') -Label "Requery=>$Type"  
}
