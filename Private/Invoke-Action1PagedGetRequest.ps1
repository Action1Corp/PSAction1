function Invoke-Action1PagedGetRequest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Label,
        [string]$AddArgs,
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Offset = 0,
        [ValidateRange(1, [int]::MaxValue)]
        [int]$Limit = 200
    )

    $RequestArgs = $AddArgs
    $RequestArgs = Join-QueryString -QueryString $RequestArgs -Argument "from=$Offset"
    $RequestArgs = Join-QueryString -QueryString $RequestArgs -Argument "limit=$Limit"

    $Page = Invoke-Action1ApiRequest -Method GET -Path $Path -Label $Label -AddArgs $RequestArgs

    if ($null -eq $Page) {
        Write-Action1Debug "[$Label] Page 1 returned null. Stopping pagination."
        return $null
    }

    if ($Page.PSObject.Properties.Name -notcontains 'items') {
        Write-Action1Debug "[$Label] Response is not a paged result. Returning response as-is."
        $Page
        return
    }

    $GetPageItemCount = {
        param([object]$CurrentPage)

        if ($null -eq $CurrentPage) {
            return 0
        }

        if ($CurrentPage.PSObject.Properties.Name -notcontains 'items') {
            return 0
        }

        if ($null -eq $CurrentPage.items) {
            return 0
        }

        return @($CurrentPage.items).Count
    }

    $PageNumber = 1
    $ItemCount = & $GetPageItemCount $Page

    Write-Action1Debug "[$Label] Processing page $PageNumber. Items: $ItemCount"

    foreach ($Item in @($Page.items)) {
        $Item
    }

    while (-not [string]::IsNullOrEmpty($Page.next_page)) {
        $PageNumber++
        Write-Action1Debug "[$Label] Requesting page $PageNumber..."

        $Page = Invoke-Action1ApiRequest -Method GET -Path $Page.next_page -Label $Label

        if ($null -eq $Page) {
            Write-Action1Debug "[$Label] Page $PageNumber returned null. Stopping pagination."
            break
        }

        $ItemCount = & $GetPageItemCount $Page
        Write-Action1Debug "[$Label] Processing page $PageNumber. Items: $ItemCount"

        foreach ($Item in @($Page.items)) {
            $Item
        }
    }
}