# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Test-CsvHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CsvPath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$RequiredColumns,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$FileLabel = 'CSV'
    )

    $actualColumns = @(Get-CsvHeader -CsvPath $CsvPath)

    if ($actualColumns.Count -eq 0) {
        Write-Error "$FileLabel CSV file '$CsvPath' does not contain a header row." `
            -ErrorAction Stop
    }

    $headerObject = [pscustomobject]@{}

    foreach ($actualColumn in $actualColumns) {
        if ([string]::IsNullOrWhiteSpace($actualColumn)) {
            continue
        }

        $headerObject |
            Add-Member `
                -MemberType NoteProperty `
                -Name $actualColumn `
                -Value $null `
                -Force
    }

    $objectName = "$FileLabel CSV header"

    if (-not (Test-ObjectProperties $headerObject $RequiredColumns $objectName)) {
        $missingColumns = @(
            $RequiredColumns |
                Where-Object { $actualColumns -inotcontains $_ }
        )
        $missingColumnList = $missingColumns -join ', '
        $message = (
            "$FileLabel CSV file '$CsvPath' is missing required column(s): " +
            $missingColumnList +
            '.'
        )
        Write-Error $message -ErrorAction Stop
    }

    return $true
}
