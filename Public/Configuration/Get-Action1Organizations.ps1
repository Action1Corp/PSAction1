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
    $path = "$Script:Action1_BaseURI{0}" -f $endpoint
    $requestParams = @{
        Path  = $path
        Label = 'Organizations'
    }
    $response = @(
        Invoke-Action1PagedGetRequest @requestParams |
            Where-Object { $null -ne $_ }
    )

    if ($response.Count -eq 0) {
        Write-Error 'Unable to get Action1 organizations.' -ErrorAction Stop
    }

    $organizations = $response

    $isPagedResponse = (
        $response.Count -eq 1 -and
        $response[0].PSObject.Properties.Name -contains 'items'
    )

    if ($isPagedResponse) {
        $organizations = $response[0].items
    }

    if ($null -eq $organizations) {
        $message = 'Action1 organizations response did not contain items.'
        Write-Error $message -ErrorAction Stop
    }

    $organizationList = @(
        $organizations |
            Where-Object { $null -ne $_ }
    )

    if ($organizationList.Count -eq 0) {
        $message = 'Action1 organizations response did not contain items.'
        Write-Error $message -ErrorAction Stop
    }

    $organizationList |
        ForEach-Object {
            [PSCustomObject]@{
                Org_Name = $_.name
                Org_ID   = $_.id
            }
        } |
        Sort-Object -Property Org_Name, Org_ID
}
