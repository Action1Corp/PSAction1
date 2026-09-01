# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1MappingIndexFileHeaderError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Collections.IDictionary]$HeaderValues
    )

    $pathResolver = $ExecutionContext.SessionState.Path
    $resolvedPath = $pathResolver.GetUnresolvedProviderPathFromPSPath($Path)
    $writeHeaderDebug = {
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$Message
        )

        Write-Action1Debug (
            "Mapping index file '$resolvedPath' header validation failed. " +
            $Message
        )
    }
    $newHeaderError = {
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$Message
        )

        & $writeHeaderDebug $Message
        $Message
    }

    if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
        return (& $newHeaderError 'File was not found.')
    }

    $expectedHeader = New-Action1JsonHeader `
        -HeaderTemplate $Script:Action1_MappingIndexTextHeader `
        -PropertyValues $HeaderValues
    $actualHeader = @{}
    $lineNumber = 0
    $foundHeaderEnd = $false
    $headerEndLineNumber = $expectedHeader.Count + 1
    $reader = $null

    try {
        $reader = [System.IO.File]::OpenText($resolvedPath)

        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            $lineNumber++

            if (-not $foundHeaderEnd) {
                if ($line -ceq $Script:Action1_MappingIndexTextHeaderEnd) {
                    $foundHeaderEnd = $true
                    break
                }

                if ($lineNumber -eq $headerEndLineNumber) {
                    $message = "Line $lineNumber expected "
                    $message += "'$Script:Action1_MappingIndexTextHeaderEnd' "
                    $message += "but found '$line'."
                    return (& $newHeaderError $message)
                }

                if (-not $line.StartsWith('# ')) {
                    $message = "Line $lineNumber is not a header line."
                    return (& $newHeaderError $message)
                }

                $headerLine = $line.Substring(2)
                $separatorIndex = $headerLine.IndexOf('=')

                if ($separatorIndex -lt 1) {
                    $message = "Line $lineNumber does not contain "
                    $message += "a valid '=' separator."
                    return (& $newHeaderError $message)
                }

                $propertyName = $headerLine.Substring(0, $separatorIndex).Trim()
                $propertyValue = $headerLine.Substring($separatorIndex + 1)

                if ([string]::IsNullOrWhiteSpace($propertyName)) {
                    $message = "Line $lineNumber contains an empty property name."
                    return (& $newHeaderError $message)
                }

                $actualHeader[$propertyName] = $propertyValue
                continue
            }
        }
    }
    catch {
        $message = "Failed to read the file. $($_.Exception.Message)"
        return (& $newHeaderError $message)
    }
    finally {
        if ($null -ne $reader) {
            $reader.Dispose()
        }
    }

    if ($lineNumber -eq 0) {
        return (& $newHeaderError 'File is empty.')
    }

    if (-not $foundHeaderEnd) {
        $message = "Header end marker '$Script:Action1_MappingIndexTextHeaderEnd' "
        $message += 'was not found.'
        return (& $newHeaderError $message)
    }

    foreach ($entry in $expectedHeader.GetEnumerator()) {
        $propertyName = [string]$entry.Key
        $expectedValue = [string]$entry.Value

        if (-not $actualHeader.ContainsKey($propertyName)) {
            return (& $newHeaderError "Missing required property '$propertyName'.")
        }

        if ([string]$actualHeader[$propertyName] -cne $expectedValue) {
            $actualValue = [string]$actualHeader[$propertyName]
            $message = "Property '$propertyName' has value '$actualValue'. "
            $message += "Expected '$expectedValue'."
            return (& $newHeaderError $message)
        }
    }

    $null
}
