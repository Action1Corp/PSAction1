# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md
# https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1ErrorResponseDetails {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [AllowNull()]
        [string]$ResponseContent
    )

    if ([string]::IsNullOrWhiteSpace($ResponseContent)) {
        return $null
    }

    try {
        $errorResponse = ConvertFrom-Json -InputObject $ResponseContent
    }
    catch {
        Write-Action1Debug (
            "Failed to parse error response details: $($_.Exception.Message)"
        )
        return $null
    }

    if ($null -eq $errorResponse) {
        return $null
    }

    if (-not (Test-ObjectProperties $errorResponse 'details' 'error response')) {
        return $null
    }

    return $errorResponse.details
}
