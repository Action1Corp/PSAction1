# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Write-JsonFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Json,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    try {
        $jsonContent = ConvertTo-Json `
            -InputObject $Json `
            -Depth $Script:Action1_JsonObjectConversionDepth
        $jsonLines = @($jsonContent -split "`r?`n")

        $writeParams = @{
            Path    = $Path
            Content = $jsonLines
        }

        if ($Force.IsPresent) {
            $writeParams.Force = $true
        }

        Write-TextFileContent @writeParams
    }
    catch {
        $message = "Failed to save JSON file '$Path'. "
        $message += $_.Exception.Message
        Write-Error $message -ErrorAction Stop
    }
}
