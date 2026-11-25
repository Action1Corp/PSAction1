# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function New-Action1AutomationActionFilter {
    [CmdletBinding(PositionalBinding = $false)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ -not [string]::IsNullOrWhiteSpace($_) })]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Values,

        [Parameter(Mandatory = $true)]
        [ValidateSet('include', 'exclude')]
        [string]$Operator
    )

    foreach ($value in $Values) {
        if ([string]::IsNullOrWhiteSpace($value)) {
            throw 'Filter Values cannot contain null, empty, or whitespace entries.'
        }
    }

    [pscustomobject][ordered]@{
        name     = $Name
        values   = @($Values)
        operator = $Operator.ToLowerInvariant()
    }
}
