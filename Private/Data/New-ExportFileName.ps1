# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function New-ExportFileName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) {
                throw 'Export file name format cannot be empty.'
            }

            $true
        })]
        [string]$FileNameFormat,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) {
                throw 'Export file timestamp template cannot be empty.'
            }

            $true
        })]
        [string]$TimestampTemplate
    )

    $timestamp = Get-UtcTimestamp -Template $TimestampTemplate

    try {
        return $FileNameFormat -f $timestamp
    }
    catch {
        $message = "Unable to format export file name from '$FileNameFormat'. "
        $message += "Error: $($_.Exception.Message)"
        throw $message
    }
}
