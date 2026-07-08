# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

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

    $hasProperty = {
        param(
            [object]$InputObject,
            [string]$PropertyName
        )

        if ($null -eq $InputObject) {
            return $false
        }

        return ($InputObject.PSObject.Properties.Name -contains $PropertyName)
    }

    $convertToInt64 = {
        param(
            [object]$Value
        )

        if ($null -eq $Value) {
            return $null
        }

        $stringValue = [string]$Value

        if ([string]::IsNullOrWhiteSpace($stringValue)) {
            return $null
        }

        $number = 0L

        if ([int64]::TryParse($stringValue, [ref]$number)) {
            return $number
        }

        return $null
    }

    $getPageItemCount = {
        param(
            [object]$CurrentPage
        )

        if ($null -eq $CurrentPage) {
            return 0
        }

        if (-not (& $hasProperty $CurrentPage 'items')) {
            return 0
        }

        if ($null -eq $CurrentPage.items) {
            return 0
        }

        return @($CurrentPage.items).Count
    }

    $removePagingArguments = {
        param(
            [string]$QueryString
        )

        if ([string]::IsNullOrWhiteSpace($QueryString)) {
            return $null
        }

        $queryParts = @(
            $QueryString -split '&' |
                Where-Object {
                    -not [string]::IsNullOrWhiteSpace($_) -and
                    $_ -notmatch '^(from|limit)='
                }
        )

        if ($queryParts.Count -eq 0) {
            return $null
        }

        return ($queryParts -join '&')
    }

    $baseArgs = & $removePagingArguments $AddArgs

    $buildPageRequestArgs = {
        param(
            [int64]$CurrentOffset,
            [int64]$CurrentLimit
        )

        $requestArgs = $baseArgs
        $requestArgs = Join-QueryString -QueryString $requestArgs -Argument "from=$CurrentOffset"
        $requestArgs = Join-QueryString -QueryString $requestArgs -Argument "limit=$CurrentLimit"

        return $requestArgs
    }

    $requestArgs = & $buildPageRequestArgs $Offset $Limit

    $page = Invoke-Action1ApiRequest -Method GET -Path $Path -Label $Label -AddArgs $requestArgs

    if ($null -eq $page) {
        Write-Action1Debug "[$Label] Page 1 returned null. Stopping pagination."
        return $null
    }

    if (-not (& $hasProperty $page 'items')) {
        Write-Action1Debug "[$Label] Response is not a paged result. Returning response as-is."
        $page
        return
    }

    $pageNumber = 1
    $itemCount = & $getPageItemCount $page

    Write-Action1Debug "[$Label] Processing page $pageNumber. Items: $itemCount"

    foreach ($item in @($page.items)) {
        $item
    }

    if (& $hasProperty $page 'next_page') {
        while (-not [string]::IsNullOrWhiteSpace([string]$page.next_page)) {
            $pageNumber++

            Write-Action1Debug "[$Label] Requesting page $pageNumber by next_page..."

            $page = Invoke-Action1ApiRequest -Method GET -Path $page.next_page -Label $Label

            if ($null -eq $page) {
                Write-Action1Debug "[$Label] Page $pageNumber returned null. Stopping pagination."
                break
            }

            if (-not (& $hasProperty $page 'items')) {
                Write-Action1Debug "[$Label] Page $pageNumber does not contain items. Stopping pagination."
                break
            }

            $itemCount = & $getPageItemCount $page

            Write-Action1Debug "[$Label] Processing page $pageNumber. Items: $itemCount"

            foreach ($item in @($page.items)) {
                $item
            }
        }

        return
    }

    Write-Action1Debug "[$Label] Response does not contain next_page. Trying total_items/from/limit pagination."

    if (
        -not (& $hasProperty $page 'total_items') -or
        -not (& $hasProperty $page 'limit') -or
        -not (& $hasProperty $page 'from')
    ) {
        Write-Action1Debug "[$Label] total_items/from/limit paging properties are incomplete. Stopping pagination."
        return
    }

    $totalItems = & $convertToInt64 $page.total_items
    $responseLimit = & $convertToInt64 $page.limit
    $responseFrom = & $convertToInt64 $page.from

    if ($null -eq $totalItems) {
        Write-Action1Debug "[$Label] total_items value '$($page.total_items)' is not numeric. Stopping pagination."
        return
    }

    if ($null -eq $responseLimit -or $responseLimit -le 0) {
        Write-Action1Debug "[$Label] limit value '$($page.limit)' is not a positive numeric value. Stopping pagination."
        return
    }

    if ($null -eq $responseFrom -or $responseFrom -lt 0) {
        Write-Action1Debug "[$Label] from value '$($page.from)' is not a valid numeric value. Stopping pagination."
        return
    }

    $nextOffset = $responseFrom + $responseLimit

    while ($nextOffset -lt $totalItems) {
        $pageNumber++

        Write-Action1Debug "[$Label] Requesting page $pageNumber by offset. from=$nextOffset; limit=$responseLimit; total_items=$totalItems"

        $requestArgs = & $buildPageRequestArgs $nextOffset $responseLimit

        $page = Invoke-Action1ApiRequest -Method GET -Path $Path -Label $Label -AddArgs $requestArgs

        if ($null -eq $page) {
            Write-Action1Debug "[$Label] Page $pageNumber returned null. Stopping pagination."
            break
        }

        if (-not (& $hasProperty $page 'items')) {
            Write-Action1Debug "[$Label] Page $pageNumber does not contain items. Stopping pagination."
            break
        }

        $itemCount = & $getPageItemCount $page

        Write-Action1Debug "[$Label] Processing page $pageNumber. Items: $itemCount"

        foreach ($item in @($page.items)) {
            $item
        }

        # Re-read paging metadata from every response because some endpoints may
        # normalize the requested limit, update total_items between requests, or
        # return unexpected paging values. This also prevents infinite loops when
        # the returned offset does not advance.
        $previousOffset = $nextOffset

        $currentTotalItems = & $convertToInt64 $page.total_items
        $currentLimit = & $convertToInt64 $page.limit
        $currentFrom = & $convertToInt64 $page.from

        if ($null -ne $currentTotalItems) {
            $totalItems = $currentTotalItems
        }

        if ($null -eq $currentLimit -or $currentLimit -le 0) {
            Write-Action1Debug "[$Label] Page $pageNumber returned invalid limit '$($page.limit)'. Stopping pagination."
            break
        }

        if ($null -eq $currentFrom -or $currentFrom -lt 0) {
            Write-Action1Debug "[$Label] Page $pageNumber returned invalid from '$($page.from)'. Stopping pagination."
            break
        }

        $responseLimit = $currentLimit
        $nextOffset = $currentFrom + $currentLimit

        if ($nextOffset -le $previousOffset) {
            Write-Action1Debug "[$Label] Next offset did not advance. Previous offset: $previousOffset; next offset: $nextOffset. Stopping pagination."
            break
        }
    }
}
