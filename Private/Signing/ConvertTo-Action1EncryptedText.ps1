# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function ConvertTo-Action1EncryptedText {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'Convert supplied text for Windows DPAPI encrypted storage.'
    )]
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Text
    )

    if ($env:OS -ne 'Windows_NT') {
        throw 'Action1 encrypted text storage is supported only on Windows.'
    }

    try {
        # -AsPlainText treats Text as plaintext and creates a SecureString object,
        # which is the input type required by ConvertFrom-SecureString below.
        $secureText = ConvertTo-SecureString -String $Text -AsPlainText -Force `
            -ErrorAction Stop

        # Despite its name, ConvertFrom-SecureString does not return plaintext
        # in Windows PowerShell 5.1. It returns an encrypted String for storage.
        # Without -Key or -SecureKey, Windows DPAPI uses the current user's context.
        ConvertFrom-SecureString -SecureString $secureText -ErrorAction Stop
    }
    catch {
        throw 'Cannot encrypt text for the current Windows user.'
    }
}
