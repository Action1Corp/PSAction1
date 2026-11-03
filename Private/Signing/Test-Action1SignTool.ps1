# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Test-Action1SignTool {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    # Windows PowerShell 5.1 runs only on Windows and does not define IsWindows.
    $windowsPlatform = Get-Variable -Name IsWindows -ErrorAction SilentlyContinue
    if ($null -ne $windowsPlatform -and -not $windowsPlatform.Value) {
        throw 'Action1 object signing is supported only on Windows.'
    }

    if (
        $Script:Action1_SignToolPath -notmatch '\S' -or
        $Script:Action1_SignToolFileName -notmatch '\S'
    ) {
        throw 'Action1 signing tool directory or filename is not configured.'
    }

    $signToolPath = Join-Path $Script:Action1_SignToolPath `
        $Script:Action1_SignToolFileName -ErrorAction Stop
    if (Test-Path -LiteralPath $signToolPath -PathType Leaf -ErrorAction Stop) {
        return $true
    }

    Write-Action1Debug "Action1 signing tool was not found at '$signToolPath'."
    return $false
}
