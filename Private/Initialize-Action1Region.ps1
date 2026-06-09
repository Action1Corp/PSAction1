function Initialize-Action1Region {
    [CmdletBinding()]
    param()

    if (-not [string]::IsNullOrWhiteSpace($Script:Action1_BaseURI)) {
        return $true
    }

    if (-not $Script:Action1_Interactive) {
        throw "Region not set. Call Set-Action1Region prior to making API calls."
    }

    $regions = @($Script:Action1_Hosts.GetEnumerator())

    while ([string]::IsNullOrWhiteSpace($Script:Action1_BaseURI)) {

        for ($i = 0; $i -lt $regions.Count; $i++) {
            Write-Host "$i : $($regions[$i].Key)"
        }

        $selection = Read-Host -Prompt 'Select your data center region'

        $index = 0
        if (
            [int]::TryParse($selection, [ref]$index) -and
            $index -ge 0 -and
            $index -lt $regions.Count
        ) {
            $Script:Action1_BaseURI = $regions[$index].Value
        }
        else {
            Write-Warning "Invalid selection."
        }
    }
    return $true
}