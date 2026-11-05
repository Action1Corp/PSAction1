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

    try {
        # Windows PowerShell 5.1 runs only on Windows and does not define IsWindows.
        $windowsPlatform = Get-Variable -Name IsWindows -ErrorAction SilentlyContinue
        if ($null -ne $windowsPlatform -and -not $windowsPlatform.Value) {
            throw 'Action1 object signing is supported only on Windows.'
        }

        if (
            [string]::IsNullOrWhiteSpace($Script:Action1_SignToolPath) -or
            [string]::IsNullOrWhiteSpace($Script:Action1_SignToolFileName)
        ) {
            throw 'Action1 signing tool directory or filename is not configured.'
        }
        if ($Script:Action1_SignToolSha256 -notmatch $Script:Action1_Sha256ValidationPattern) {
            throw 'Action1 signing tool executable SHA256 is not configured or invalid.'
        }

        $signToolPath = Join-Path $Script:Action1_SignToolPath `
            $Script:Action1_SignToolFileName -ErrorAction Stop
        if (-not (Test-Path -LiteralPath $signToolPath -PathType Leaf -ErrorAction Stop)) {
            Write-Action1Debug "Action1 signing tool was not found at '$signToolPath'."
            $null = Get-Action1SignTool -ErrorAction Stop
        }

        if (-not (Test-HashCode -Path $signToolPath `
            -ExpectedHash $Script:Action1_SignToolSha256)) {
            throw 'Action1 signing tool executable SHA256 mismatch.'
        }

        return $true
    }
    catch {
        Write-Action1Debug "Action1 signing tool validation failed: $($_.Exception.Message)"
        return $false
    }
}
