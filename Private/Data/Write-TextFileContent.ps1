# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Write-TextFileContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Content,

        [Parameter(Mandatory = $false)]
        [switch]$Append,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    $contentParams = @{
        LiteralPath = $Path
        Value       = $Content
        Encoding    = 'UTF8'
    }

    if ($Force.IsPresent) {
        $contentParams.Force = $true
    }

    try {
        if ($Append.IsPresent) {
            Add-Content @contentParams -ErrorAction Stop
        }
        else {
            Set-Content @contentParams -ErrorAction Stop
        }
    }
    catch {
        $message = New-TextFileWriteErrorMessage `
            -Operation 'write file' `
            -Path $Path `
            -ErrorMessage $_.Exception.Message

        throw $message
    }
}
