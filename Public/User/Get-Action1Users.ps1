# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1Users {
    [CmdletBinding(DefaultParameterSetName = 'AllUsers')]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = 'AsPage')]
        [switch]$AsPage,

        [Parameter(Mandatory = $false)]
        [ValidateScript({
            Test-Action1PageSize `
                -Value $_ `
                -Maximum $Script:Action1_PagedGetRequestDefaultLimit `
                -ParameterName 'Limit'
        })]
        [int]$Limit = $Script:Action1_PagedGetRequestDefaultLimit
    )

    $uriPathBuilder = Get-UriMapValue -Key 'G_Users'

    $uri = & $uriPathBuilder
    $path = "$Script:Action1_BaseURI{0}" -f $uri

    Write-Action1Debug 'Listing Action1 users.'

    $requestParams = @{
        Path  = $path
        Label = 'Users'
        Limit = $Limit
    }

    if ($AsPage.IsPresent) {
        $requestParams.AsPage = $true
    }

    if ($AsPage.IsPresent) {
        Invoke-Action1PagedGetRequest @requestParams |
            Where-Object { $null -ne $_ } |
            ForEach-Object {
                $userList = @(
                    $_.Items |
                        Where-Object { $null -ne $_ }
                )

                [PSCustomObject][ordered]@{
                    Items      = $userList
                    PageNumber = $_.PageNumber
                    From       = $_.From
                    Limit      = $_.Limit
                    TotalItems = $_.TotalItems
                    NextPage   = $_.NextPage
                }
            }

        return
    }

    Invoke-Action1PagedGetRequest @requestParams
}

