# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Test-Action1ExportFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$Force,

        [Parameter(Mandatory = $true)]
        [ValidateSet('JSON', 'CSV', 'TXT')]
        [string]$FileType
    )

    $fileTypeLabel = ([string]$FileType).Trim().ToUpperInvariant()

    if (
        (Test-Path -LiteralPath $Path -PathType Leaf) -and
        -not $Force.IsPresent
    ) {
        $message = "The $fileTypeLabel export file '$Path' already exists. "
        $message += 'Use -Force to overwrite it.'
        throw $message
    }

    $true
}
