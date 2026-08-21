# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Update-Action1User {
    [CmdletBinding(SupportsShouldProcess = $true, PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if (-not (Test-Guid $_)) {
                throw 'UserId must be in the standard GUID format.'
            }

            $true
        })]
        [string]$UserId,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$FirstName,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$LastName,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')]
        [string]$Email,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^\+?\d{6,13}$')]
        [string]$Phone,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9_+-]*/[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*$')]
        [string]$Timezone,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Disabled users are not returned by Get-Action1Users. Retrieve disabled users by ID with Get-Action1User.'
        )]
        [ValidateSet('yes', 'no')]
        [string]$Enabled,

        [Parameter(Mandatory = $false)]
        [ValidateRange(5, 1440)]
        [int]$SessionTimeout,

        [switch]$Force
    )

    $body = [ordered]@{}

    if ($PSBoundParameters.ContainsKey('FirstName')) {
        $body.first_name = $FirstName
    }

    if ($PSBoundParameters.ContainsKey('LastName')) {
        $body.last_name = $LastName
    }

    if ($PSBoundParameters.ContainsKey('Email')) {
        $body.email = $Email
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

    if ($body.Count -eq 0) {
        Write-Error 'Specify at least one value to update.'
        return
    }

    $uriPathBuilder = Get-UriMapValue -Key 'U_User'

    $uri = & $uriPathBuilder $UserId
    $path = "$Script:Action1_BaseURI{0}" -f $uri
    $userLabel = "User '$UserId'"

    if ($Force) {
        $ConfirmPreference = 'None'
    }

    if (-not $PSCmdlet.ShouldProcess($userLabel, 'Update Action1 user')) {
        Write-Action1Debug "Skipped updating user '$UserId'."
        return
    }

    Write-Action1Debug "Updating user '$UserId'."

    $response = Invoke-Action1ApiRequest `
        -Method PATCH `
        -Path $path `
        -Label "Update user '$UserId'" `
        -Body $body

    if ($null -eq $response) {
        Write-Error "Failed to update user '$UserId'."
        return
    }

    Write-Action1Debug "Updated user '$UserId'."

    $response
}
