# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1SignTool {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if (Test-Action1SignTool) {
        return (Join-Path $Script:Action1_SignToolPath $Script:Action1_SignToolFileName)
    }

    $signToolLastRelease = Get-Action1SignToolLastRelease

    $null = New-Item -ItemType Directory -Path $Script:Action1_SignToolPath `
        -Force -ErrorAction Stop
    $signToolDirectory = (Resolve-Path -LiteralPath $Script:Action1_SignToolPath).ProviderPath
    $signToolPath = Join-Path $signToolDirectory $Script:Action1_SignToolFileName
    $stagingName = 'download-' + (New-Guid).Guid
    $stagingDirectory = (New-Item -ItemType Directory -Path $signToolDirectory `
        -Name $stagingName -ErrorAction Stop).FullName

    try {
        $zipFile = Join-Path $stagingDirectory 'action1sign.zip'
        $extractDirectory = Join-Path $stagingDirectory 'extracted'

        Write-Action1Debug "Downloading Action1 signing tool $($signToolLastRelease.Version)."
        Invoke-WebRequest -Uri $signToolLastRelease.Url -OutFile $zipFile `
            -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop

        $actualHash = (Get-FileHash -LiteralPath $zipFile -Algorithm SHA256 -ErrorAction Stop).Hash
        if ($actualHash -ne $signToolLastRelease.Sha256) {
            throw 'Action1 signing tool ZIP SHA256 mismatch. Installation was cancelled.'
        }

        Expand-Archive -LiteralPath $zipFile -DestinationPath $extractDirectory -ErrorAction Stop
        $executables = @(Get-ChildItem -LiteralPath $extractDirectory -File -Recurse `
            -ErrorAction Stop | Where-Object {
            $_.Name -eq $Script:Action1_SignToolFileName
        })
        if ($executables.Count -ne 1 -or $executables[0].Length -eq 0) {
            throw 'Action1 signing tool ZIP must contain exactly one nonempty signing executable.'
        }

        Move-Item -LiteralPath $executables[0].FullName -Destination $signToolPath -ErrorAction Stop
        Write-Action1Debug "Installed Action1 signing tool at '$signToolPath'."
        return $signToolPath
    }
    finally {
        if (Test-Path -LiteralPath $stagingDirectory -PathType Container) {
            $resolvedStaging = (Resolve-Path -LiteralPath $stagingDirectory).ProviderPath
            if ((Split-Path -Path $resolvedStaging -Parent) -eq $signToolDirectory) {
                Remove-Item -LiteralPath $resolvedStaging -Recurse -Force `
                    -ErrorAction SilentlyContinue
            }
        }
    }
}
