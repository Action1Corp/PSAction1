# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Get-Action1SignToolLastRelease {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    if ([string]::IsNullOrWhiteSpace($Script:Action1_SignToolReleaseApiUrl)) {
        throw 'Action1 signing tool release URL is not configured.'
    }
    if ([string]::IsNullOrWhiteSpace($Script:Action1_SignToolAssetPattern)) {
        throw 'Action1 signing tool asset pattern is not configured.'
    }

    $headers = @{
        'User-Agent' = 'PSAction1'
        'Accept' = 'application/vnd.github+json'
        'X-GitHub-Api-Version' = '2022-11-28'
    }
    Write-Action1Debug 'Resolving the latest Action1 signing tool release.'
    $release = Invoke-Action1ApiRequest -Method GET `
        -Path $Script:Action1_SignToolReleaseApiUrl -Headers $headers `
        -Label 'Action1 signing tool latest release' -SkipAuthenticationCheck `
        -ErrorAction Stop
    if (
        $null -eq $release -or
        [string]::IsNullOrWhiteSpace($release.tag_name) -or
        $release.draft -or $release.prerelease
    ) {
        throw 'GitHub did not return a published stable Action1 signing tool release.'
    }

    $assets = @($release.assets | Where-Object {
        $_.name -like $Script:Action1_SignToolAssetPattern
    })
    if ($assets.Count -ne 1) {
        throw 'Expected exactly one Windows ZIP asset in the Action1 signing tool release.'
    }
    $asset = $assets[0]
    if ([string]::IsNullOrWhiteSpace($asset.browser_download_url)) {
        throw 'Action1 signing tool ZIP asset does not provide a download URL.'
    }

    $digest = [string]$asset.digest
    if ($digest -match '^sha256:([a-fA-F0-9]{64})$') {
        $sha256 = $Matches[1].ToLowerInvariant()
    }
    elseif ([string]::IsNullOrWhiteSpace($digest)) {
        $checksumAssets = @($release.assets | Where-Object {
            $_.name -eq ($asset.name + '.sha256')
        })
        if (
            $checksumAssets.Count -ne 1 -or
            [string]::IsNullOrWhiteSpace($checksumAssets[0].browser_download_url)
        ) {
            throw 'Action1 signing tool release does not provide a SHA256 checksum.'
        }
        $checksumText = Invoke-Action1ApiRequest -Method GET `
            -Path $checksumAssets[0].browser_download_url `
            -Headers @{ 'User-Agent' = 'PSAction1'; 'Accept' = 'text/plain' } `
            -Label 'Action1 signing tool ZIP checksum' -SkipAuthenticationCheck `
            -RawResponse -ErrorAction Stop
        if ($checksumText -is [array]) {
            # RawResponse may enumerate bytes returned for an octet-stream asset.
            $checksumText = [Text.Encoding]::UTF8.GetString([byte[]]$checksumText)
        }
        $checksumPattern = '^([a-fA-F0-9]{64})(?:\s+\*?' +
            [regex]::Escape($asset.name) + ')?$'
        if (([string]$checksumText).Trim() -notmatch $checksumPattern) {
            throw 'Action1 signing tool checksum file does not contain a valid ZIP SHA256.'
        }
        $sha256 = $Matches[1].ToLowerInvariant()
    }
    else {
        throw 'Action1 signing tool ZIP digest must contain a valid SHA256 checksum.'
    }

    [PSCustomObject]@{
        Version = [string]$release.tag_name
        FileName = [string]$asset.name
        Url = [string]$asset.browser_download_url
        Sha256 = $sha256
    }
}
