# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Write-Action1MappingIndexRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SourceId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TargetId,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    $sourceIdValue = $SourceId.Trim()
    $targetIdValue = $TargetId.Trim()

    if ([string]::IsNullOrWhiteSpace($sourceIdValue)) {
        Write-Error 'Source ID cannot be empty.' -ErrorAction Stop
    }

    if ([string]::IsNullOrWhiteSpace($targetIdValue)) {
        Write-Error 'Target ID cannot be empty.' -ErrorAction Stop
    }

    if ($SourceId -match '[\t\r\n]' -or $TargetId -match '[\t\r\n]') {
        Write-Error 'Mapping index IDs cannot contain tabs or line breaks.' `
            -ErrorAction Stop
    }

    $writeParams = @{
        Path    = $Path
        Content = "$sourceIdValue`t$targetIdValue"
        Append  = $true
    }

    if ($Force.IsPresent) {
        $writeParams.Force = $true
    }

    Write-TextFileContent @writeParams
}
