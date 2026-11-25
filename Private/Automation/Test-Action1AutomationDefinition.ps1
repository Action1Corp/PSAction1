# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Test-Action1AutomationDefinition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [object]$Configuration,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [ValidateNotNull()]
        [object[]]$Endpoints,

        [Parameter(Mandatory = $true)]
        [ValidateSet('RunNow', 'Schedule')]
        [string]$Operation
    )

    if (
        $Configuration -isnot [System.Collections.IDictionary] -and
        $Configuration -isnot [PSCustomObject]
    ) {
        throw 'Configuration must be a dictionary or PSCustomObject.'
    }
    $config = [pscustomobject]$Configuration
    if ($config.name -isnot [string] -or [string]::IsNullOrWhiteSpace($config.name)) {
        throw 'The automation name must be a nonempty string.'
    }

    $retryMinutes = 0
    if (
        -not [int]::TryParse([string]$config.retry_minutes, [ref]$retryMinutes) -or
        $retryMinutes -lt 1
    ) {
        throw 'RetryMinutes must be a positive integer.'
    }

    if ($config.actions -isnot [array] -or $config.actions.Count -eq 0) {
        throw 'Actions must be a nonempty array of automation action objects.'
    }

    foreach ($action in $config.actions) {
        if ($null -eq $action) {
            throw 'Actions cannot contain null entries.'
        }
        $null = Test-Action1AutomationAction -Action $action
    }

    if ($Operation -eq 'Schedule') {
        if (
            $config.settings -isnot [string] -or
            [string]::IsNullOrWhiteSpace($config.settings) -or
            $config.settings_timezone -isnot [string] -or
            [string]::IsNullOrWhiteSpace($config.settings_timezone)
        ) {
            throw 'Schedule settings and settings_timezone must be nonempty strings.'
        }
    }

    if ($Endpoints.Count -eq 0) {
        if ($Operation -ne 'Schedule' -or $config.settings.Trim() -cne 'DISABLED') {
            throw 'Empty Endpoints are supported only for a DISABLED schedule.'
        }
    }
    foreach ($endpoint in $Endpoints) {
        if ($null -eq $endpoint) {
            throw 'Endpoints cannot contain null entries.'
        }
        if (
            $endpoint -isnot [System.Collections.IDictionary] -and
            $endpoint -isnot [PSCustomObject]
        ) {
            throw 'Each endpoint reference must be a dictionary or PSCustomObject.'
        }
        $target = [pscustomobject]$endpoint
        if ($target.id -isnot [string] -or $target.type -isnot [string]) {
            throw 'Each endpoint reference must have id and type strings.'
        }
        $null = New-Action1AutomationTarget -Id $target.id -Type $target.type
    }
    return $true
}
