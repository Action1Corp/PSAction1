# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Read-Action1MappingIndex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $pathResolver = $ExecutionContext.SessionState.Path
    $resolvedPath = $pathResolver.GetUnresolvedProviderPathFromPSPath($Path)

    if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
        $message = "Mapping index file '$resolvedPath' was not found."
        Write-Error $message -ErrorAction Stop
    }

    $sourceIds = @()
    $targetIds = @{}
    $lineNumber = 0
    $foundHeaderEnd = $false
    $reader = $null

    try {
        $reader = [System.IO.File]::OpenText($resolvedPath)

        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            $lineNumber++

            if (-not $foundHeaderEnd) {
                if ($line -ceq $Script:Action1_MappingIndexTextHeaderEnd) {
                    $foundHeaderEnd = $true
                }

                continue
            }

            if ([string]::IsNullOrWhiteSpace($line) -and -not $line.Contains("`t")) {
                continue
            }

            $fields = $line.Split([char]9)

            if (
                $fields.Count -ne 2 -or
                [string]::IsNullOrWhiteSpace($fields[0]) -or
                [string]::IsNullOrWhiteSpace($fields[1])
            ) {
                $message = "Mapping index file '$resolvedPath' line $lineNumber "
                $message += 'must contain a source ID and target ID separated by one tab.'
                Write-Error $message -ErrorAction Stop
            }

            $sourceId = $fields[0].Trim()
            $targetId = $fields[1].Trim()

            if (
                $targetIds.ContainsKey($sourceId) -and
                $targetIds[$sourceId] -cne $targetId
            ) {
                $message = "Mapping index file '$resolvedPath' line $lineNumber "
                $message += "contains conflicting target IDs for source ID '$sourceId'."
                Write-Error $message -ErrorAction Stop
            }

            $targetIds[$sourceId] = $targetId
            $sourceIds += $sourceId
        }
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.RuntimeException]) {
            throw
        }

        $message = "Failed to read mapping index source IDs from "
        $message += "'$resolvedPath'. "
        $message += $_.Exception.Message
        Write-Error $message -ErrorAction Stop
    }
    finally {
        if ($null -ne $reader) {
            $reader.Dispose()
        }
    }

    if (-not $foundHeaderEnd) {
        $message = "Mapping index file '$resolvedPath' is missing "
        $message += "$Script:Action1_MappingIndexTextHeaderEnd."
        Write-Error $message -ErrorAction Stop
    }

    $sourceIds
}
