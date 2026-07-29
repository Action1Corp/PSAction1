# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Get-CsvHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CsvPath
    )

    if ([string]::IsNullOrWhiteSpace($CsvPath)) {
        Write-Error 'CSV path cannot be empty or whitespace.' -ErrorAction Stop
    }

    if (-not (Test-Path -LiteralPath $CsvPath -PathType Leaf)) {
        Write-Error "CSV file '$CsvPath' was not found." -ErrorAction Stop
    }

    $headerLine = Get-Content -LiteralPath $CsvPath -TotalCount 1 -ErrorAction Stop

    if ([string]::IsNullOrWhiteSpace($headerLine)) {
        return
    }

    $headerLine -split ',' |
        ForEach-Object { ([string]$_).Trim().Trim('"') }
}
