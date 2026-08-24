# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Remove-QueryParameters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$QueryString,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$QueryParams
    )

    if ([string]::IsNullOrWhiteSpace($QueryString)) {
        return $null
    }

    $queryParamsToRemove = @(
        $QueryParams |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { ([string]$_).Trim() }
    )

    if ($queryParamsToRemove.Count -eq 0) {
        return $QueryString
    }

    $queryParts = @(
        $QueryString.TrimStart('?') -split '&' |
            Where-Object {
                if ([string]::IsNullOrWhiteSpace($_)) {
                    return $false
                }

                $queryParamName = ([string]$_ -split '=', 2)[0]
                return ($queryParamsToRemove -inotcontains $queryParamName)
            }
    )

    if ($queryParts.Count -eq 0) {
        return $null
    }

    return ($queryParts -join '&')
}
