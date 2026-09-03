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

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    $sourceIdValue = $SourceId.Trim()

    if ([string]::IsNullOrWhiteSpace($sourceIdValue)) {
        Write-Error 'Source ID cannot be empty.' -ErrorAction Stop
    }

    $writeParams = @{
        Path    = $Path
        Content = $sourceIdValue
        Append  = $true
    }

    if ($Force.IsPresent) {
        $writeParams.Force = $true
    }

    Write-TextFileContent @writeParams
}
