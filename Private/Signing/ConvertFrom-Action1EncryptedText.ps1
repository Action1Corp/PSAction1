# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function ConvertFrom-Action1EncryptedText {
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
        # Without -AsPlainText, ConvertTo-SecureString expects the encrypted String
        # produced by ConvertFrom-SecureString. Here Windows DPAPI decrypts it in
        # the current user's context and returns a SecureString, not plaintext.
        $secureText = ConvertTo-SecureString -String $Text -ErrorAction Stop
        if ($secureText.Length -eq 0) {
            throw 'Empty encrypted value.'
        }
        # Windows PowerShell 5.1 has no ConvertFrom-SecureString -AsPlainText.
        # Password exposes the SecureString value as an ordinary plaintext String.
        # The username is only a placeholder; no connection or authentication occurs.
        $credential = New-Object -TypeName System.Net.NetworkCredential `
            -ArgumentList 'Action1', $secureText -ErrorAction Stop
        $credential.Password
    }
    catch {
        throw 'Cannot decrypt encrypted text for the current Windows user.'
    }
}
