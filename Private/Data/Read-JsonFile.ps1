# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Read-JsonFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $pathResolver = $ExecutionContext.SessionState.Path
    $resolvedPath = $pathResolver.GetUnresolvedProviderPathFromPSPath($Path)

    if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
        $message = "JSON file '$resolvedPath' was not found."
        Write-Action1Debug $message
        Write-Error $message -ErrorAction Stop
    }

    try {
        $jsonContent = Get-Content `
            -LiteralPath $resolvedPath `
            -Raw `
            -ErrorAction Stop

        return ConvertFrom-Json -InputObject $jsonContent -ErrorAction Stop
    }
    catch {
        $message = "Failed to read JSON file '$resolvedPath'. "
        $message += $_.Exception.Message
        Write-Action1Debug $message
        Write-Error $message -ErrorAction Stop
    }
}
