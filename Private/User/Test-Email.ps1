# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Test-Email {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Email
    )

    if (
        [string]::IsNullOrWhiteSpace($Email) -or
        $Email -notmatch $Script:Action1_EmailValidationPattern
    ) {
        $message = (
            'The argument "{0}" does not match the "{1}" pattern. ' +
            'Supply an argument that matches "{1}" and try the command again.'
        ) -f $Email, $Script:Action1_EmailValidationPattern

        throw $message
    }

    $true
}
