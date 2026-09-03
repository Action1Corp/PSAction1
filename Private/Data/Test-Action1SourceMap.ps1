# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Test-Action1SourceMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$MapObject,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$SourceObjectId
    )

    if ($null -eq $MapObject) {
        return $false
    }

    if ([string]::IsNullOrWhiteSpace($SourceObjectId)) {
        return $false
    }

    $sourceObjectIdValue = $SourceObjectId.Trim()

    return ($null -ne $MapObject.PSObject.Properties[$sourceObjectIdValue])
}
