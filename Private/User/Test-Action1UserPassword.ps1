# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Test-Action1UserPassword {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingPlainTextForPassword',
        'Password',
        Justification = 'Validates the password string required by the Action1 users API.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Password
    )

    if (
        [string]::IsNullOrWhiteSpace($Password) -or
        $Password.Length -lt 12 -or
        $Password -notmatch '\d' -or
        $Password -cnotmatch '[A-Z]' -or
        $Password -cnotmatch '[a-z]'
    ) {
        $message = 'User password must be at least 12 characters long, '
        $message += 'contain at least one number, and contain upper '
        $message += 'and lower case letters.'
        throw $message
    }

    $true
}
