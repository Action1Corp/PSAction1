# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Add-Action1Signature {
    <#
    .SYNOPSIS
    Signs a configuration and attaches its signature to the supplied request.
    .DESCRIPTION
    Accepts a dictionary or PSCustomObject request, such as an API 4 Automation
    definition. ConfigurationProperty selects its configuration object. Use an
    empty ConfigurationProperty to sign the root object, excluding signatures.
    Preserves a valid configuration GUID or generates one if absent or empty.
    Its type and organization_id are required and copied to object_reference.
    On success, updates and returns the supplied object. Replaces signatures
    with one entry so stale signatures are not retained after configuration edits.
    Only the configuration's top level is copied for signing; nested values are
    reused. No input properties are changed if signing fails. Uses the current
    session's signing credentials unless explicit credentials are supplied.
    .EXAMPLE
    $signedBody = Add-Action1Signature -InputObject $automationDefinition
    .EXAMPLE
    $signedBody = Add-Action1Signature -InputObject $body -ConfigurationProperty policy
    .EXAMPLE
    $signedObject = Add-Action1Signature -InputObject $config -ConfigurationProperty ''
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.IDictionary], [PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [object]$InputObject,

        [AllowEmptyString()]
        [ValidateNotNull()]
        [string]$ConfigurationProperty = 'configuration',

        [string]$Action1KeyPath = $Script:Action1_SignKeyPath,

        [System.Security.SecureString]$Passphrase = $Script:Action1_SignPassphrase
    )

    if (
        $InputObject -isnot [System.Collections.IDictionary] -and
        $InputObject -isnot [PSCustomObject]
    ) {
        throw 'InputObject must be a dictionary or PSCustomObject request.'
    }
    if (
        $ConfigurationProperty -ne '' -and
        ([string]::IsNullOrWhiteSpace($ConfigurationProperty) -or
            $ConfigurationProperty -ieq 'signatures')
    ) {
        throw 'ConfigurationProperty must identify a configuration, not signatures or whitespace.'
    }

    $configuration = $InputObject
    if ($ConfigurationProperty -ne '') {
        if ($InputObject -is [System.Collections.IDictionary]) {
            $configuration = $InputObject[$ConfigurationProperty]
        }
        else {
            $property = $InputObject.PSObject.Properties[$ConfigurationProperty]
            $configuration = if ($null -ne $property) { $property.Value } else { $null }
        }
    }
    if (
        $configuration -isnot [System.Collections.IDictionary] -and
        $configuration -isnot [PSCustomObject]
    ) {
        throw 'The selected configuration must be a dictionary or PSCustomObject.'
    }

    # Stage the configuration without mutating the caller's object.
    $configurationProperties = [ordered]@{}
    if ($configuration -is [System.Collections.IDictionary]) {
        foreach ($key in $configuration.Keys) {
            $configurationProperties[$key] = $configuration[$key]
        }
    }
    else {
        foreach ($property in $configuration.PSObject.Properties) {
            $configurationProperties[$property.Name] = $property.Value
        }
    }
    if ($ConfigurationProperty -eq '') {
        $configurationProperties.Remove('signatures')
    }
    $configurationType = $configurationProperties['type']
    if (
        $configurationType -isnot [string] -or
        [string]::IsNullOrWhiteSpace($configurationType)
    ) {
        throw 'The configuration type must be a nonempty string.'
    }
    $organizationId = $configurationProperties['organization_id']
    if ($organizationId -isnot [string]) {
        throw 'The configuration organization_id must be a GUID string.'
    }
    $null = Test-Guid -Guid $organizationId -Label 'Configuration organization_id'
    $configurationId = $configurationProperties['id']
    if ($null -eq $configurationId -or
        ($configurationId -is [string] -and [string]::IsNullOrWhiteSpace($configurationId))) {
        $configurationId = (New-Guid).Guid
    }
    elseif ($configurationId -isnot [string]) {
        throw 'The configuration id must be a GUID string.'
    }
    $null = Test-Guid -Guid $configurationId -Label 'Configuration id'
    $configurationProperties['id'] = $configurationId
    $signedConfiguration = [pscustomobject]$configurationProperties
    $signature = New-Action1Signature -ObjectConfig $signedConfiguration `
        -Action1KeyPath $Action1KeyPath -Passphrase $Passphrase -ErrorAction Stop
    $signatures = @([pscustomobject][ordered]@{
        object_reference = [pscustomobject][ordered]@{
            type = $configurationType
            id = $signedConfiguration.id
            organization_id = $organizationId
        }
        object_signature = $signature
    })

    Write-Action1Debug 'Attaching signature to the Action1 request.'
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($ConfigurationProperty -eq '') {
            $InputObject['id'] = $signedConfiguration.id
        }
        else {
            $InputObject[$ConfigurationProperty] = $signedConfiguration
        }
        $InputObject['signatures'] = $signatures
    }
    else {
        $propertyName = if ($ConfigurationProperty -eq '') { 'id' } else { $ConfigurationProperty }
        $propertyValue = if ($ConfigurationProperty -eq '') {
            $signedConfiguration.id
        }
        else {
            $signedConfiguration
        }
        $InputObject | Add-Member -NotePropertyName $propertyName `
            -NotePropertyValue $propertyValue -Force
        $InputObject | Add-Member -NotePropertyName signatures `
            -NotePropertyValue $signatures -Force
    }
    return $InputObject
}
