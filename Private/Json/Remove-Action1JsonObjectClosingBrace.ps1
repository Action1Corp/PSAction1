# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Remove-Action1JsonObjectClosingBrace {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $pathResolver = $ExecutionContext.SessionState.Path
    $resolvedPath = $pathResolver.GetUnresolvedProviderPathFromPSPath($Path)

    if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
        $message = "JSON file '$resolvedPath' was not found."
        Write-Error $message -ErrorAction Stop
    }

    $stream = $null

    try {
        $stream = [System.IO.File]::Open(
            $resolvedPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None
        )

        if ($stream.Length -eq 0) {
            $message = "JSON file '$resolvedPath' is empty."
            Write-Error $message -ErrorAction Stop
        }

        $position = $stream.Length - 1

        while ($position -ge 0) {
            $stream.Position = $position
            $byteValue = $stream.ReadByte()

            if ($byteValue -in @(0x09, 0x0A, 0x0D, 0x20)) {
                $position--
                continue
            }

            if ($byteValue -ne 0x7D) {
                $message = "JSON file '$resolvedPath' does not end with "
                $message += 'an object closing brace.'
                Write-Error $message -ErrorAction Stop
            }

            $stream.SetLength($position)
            return
        }

        $message = "JSON file '$resolvedPath' does not contain content."
        Write-Error $message -ErrorAction Stop
    }
    catch {
        if ($_.Exception -is [System.Management.Automation.RuntimeException]) {
            throw
        }

        $message = "Failed to remove JSON object closing brace from "
        $message += "'$resolvedPath'. "
        $message += $_.Exception.Message
        Write-Error $message -ErrorAction Stop
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}
