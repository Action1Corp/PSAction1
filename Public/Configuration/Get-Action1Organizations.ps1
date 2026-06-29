# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Get-Action1Organizations {
    [CmdletBinding()]
    param()

    Write-Action1Debug 'Getting Action1 organizations.'

    if (-not $Script:Action1_UriMap.ContainsKey('G_Organizations')) {
        $message = "Action1 URI map key 'G_Organizations' is not defined."
        Write-Error $message -ErrorAction Stop
    }

    $endpoint = & $Script:Action1_UriMap['G_Organizations']
    $Path = "$Script:Action1_BaseURI{0}" -f $endpoint
    $requestParams = @{
        Method = 'GET'
        Path   = $Path
        Label  = 'Organizations'
    }
    $organizations = Invoke-Action1ApiRequest @requestParams

    if ($null -eq $organizations) {
        Write-Error 'Unable to get Action1 organizations.' -ErrorAction Stop
    }

    @($organizations) |
        ForEach-Object {
            [PSCustomObject]@{
                Org_Name = $_.name
                Org_ID   = $_.id
            }
        } |
        Sort-Object -Property Org_Name, Org_ID
}
