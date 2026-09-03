# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function New-Action1MappingIndexFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Collections.IDictionary]$HeaderValues,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    $content = New-Action1MappingIndexHeaderContent `
        -HeaderValues $HeaderValues

    $writeParams = @{
        Path    = $Path
        Content = $content
    }

    if ($Force.IsPresent) {
        $writeParams.Force = $true
    }

    Write-TextFileContent @writeParams
}
