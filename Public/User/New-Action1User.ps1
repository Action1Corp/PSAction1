# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function New-Action1User {
    # Keep -Password as String because the API expects it in the JSON body.
    # Suppress the PSScriptAnalyzer PSAvoidUsingPlainTextForPassword rule for
    # this specific parameter to document that API contract exception.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingPlainTextForPassword',
        'Password',
        Justification = 'The Action1 users API requires an initial password value in the POST body.'
    )]
    [CmdletBinding(SupportsShouldProcess = $true, PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FirstName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LastName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')]
        [string]$Email,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if (
                $_.Length -lt 12 -or
                $_ -notmatch '\d' -or
                $_ -cnotmatch '[A-Z]' -or
                $_ -cnotmatch '[a-z]'
            ) {
                $message = 'The initial password must be at least 12 characters long, '
                $message += 'contain at least one number, and contain upper '
                $message += 'and lower case letters.'
                throw $message
            }

            $true
        })]
        [string]$Password,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(1, 30)]
        [string]$Phone,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9_+-]*/[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*$')]
        [string]$Timezone,

        [Parameter(Mandatory = $false)]
        [ValidateSet('yes', 'no')]
        [string]$Enabled,

        [Parameter(Mandatory = $false)]
        [ValidateRange(5, 1440)]
        [int]$SessionTimeout,

        [switch]$Force
    )

    $body = [ordered]@{
        first_name = $FirstName
        last_name  = $LastName
        email      = $Email
        password   = $Password
    }

    if ($PSBoundParameters.ContainsKey('Phone')) {
        $body.phone = $Phone
    }

    if ($PSBoundParameters.ContainsKey('Timezone')) {
        $body.timezone = $Timezone
    }

    if ($PSBoundParameters.ContainsKey('Enabled')) {
        $body.enabled = $Enabled.ToLowerInvariant()
    }

    if ($PSBoundParameters.ContainsKey('SessionTimeout')) {
        $body.session_timeout = $SessionTimeout * 60
    }

    $userLabel = "User '$Email'"

    if ($Force) {
        $ConfirmPreference = 'None'
    }

    if (-not $PSCmdlet.ShouldProcess($userLabel, 'Create Action1 user')) {
        Write-Action1Debug "Skipped creating user '$Email'."
        return
    }

    $uriPathBuilder = Get-UriMapValue -Key 'N_User'

    $uri = & $uriPathBuilder
    $path = "$Script:Action1_BaseURI{0}" -f $uri

    Write-Action1Debug "Creating user '$Email'."

    $response = Invoke-Action1ApiRequest `
        -Method POST `
        -Path $path `
        -Label "Create user '$Email'" `
        -Body $body

    if ($null -eq $response) {
        Write-Error "Failed to create user '$Email'."
        return
    }

    Write-Action1Debug "Created user '$Email'."

    $response
}
