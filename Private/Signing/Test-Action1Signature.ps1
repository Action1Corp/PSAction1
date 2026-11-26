# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Test-Action1Signature {
    <#
    .SYNOPSIS
    Tests whether a request contains structurally valid signature entries.
    .DESCRIPTION
    Accepts a dictionary or PSCustomObject with a nonempty signatures array.
    Each entry requires object_reference with a nonempty type and GUID strings
    for id and organization_id, and object_signature with nonempty alg, kid,
    and value strings and a positive integer iat. Returns false for malformed
    requests. This checks structure only, not cryptographic validity or trust.
    Null input is rejected by parameter validation.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [object]$InputObject
    )

    $getProperty = {
        param($value, $name)

        if ($value -is [System.Collections.IDictionary]) {
            return ,($value[$name])
        }
        if ($value -is [PSCustomObject]) {
            $property = $value.PSObject.Properties[$name]
            if ($null -ne $property) {
                return ,($property.Value)
            }
        }
        return $null
    }

    $signatures = & $getProperty $InputObject 'signatures'
    if ($signatures -isnot [System.Collections.IList] -or $signatures.Count -eq 0) {
        return $false
    }

    foreach ($entry in $signatures) {
        $reference = & $getProperty $entry 'object_reference'
        $signature = & $getProperty $entry 'object_signature'
        $type = & $getProperty $reference 'type'
        if ($type -isnot [string] -or [string]::IsNullOrWhiteSpace($type)) {
            return $false
        }
        foreach ($name in @('id', 'organization_id')) {
            $value = & $getProperty $reference $name
            if ($value -isnot [string] -or -not (Test-Guid -Guid $value)) {
                return $false
            }
        }
        foreach ($name in @('alg', 'kid', 'value')) {
            $value = & $getProperty $signature $name
            if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)) {
                return $false
            }
        }
        $issuedAt = & $getProperty $signature 'iat'
        if (($issuedAt -isnot [int] -and $issuedAt -isnot [long]) -or $issuedAt -le 0) {
            return $false
        }
    }

    return $true
}
