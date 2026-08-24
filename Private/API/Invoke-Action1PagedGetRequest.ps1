# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

function Invoke-Action1PagedGetRequest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Label,
        [string]$AddArgs,
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Offset = $Script:Action1_PagedGetRequestDefaultOffset,
        [ValidateScript({
            Test-Action1PageSize `
                -Value $_ `
                -Maximum $Script:Action1_PagedGetRequestDefaultLimit `
                -ParameterName 'Limit'
        })]
        [int]$Limit = $Script:Action1_PagedGetRequestDefaultLimit,
        [switch]$OmitInitialOffset,
        [switch]$AsPage
    )

    $asPageOutput = $AsPage.IsPresent

    $getPageItemCount = {
        param(
            [object]$CurrentPage
        )

        if ($null -eq $CurrentPage) {
            return 0
        }

        $propertyParams = @{
            InputObject   = $CurrentPage
            PropertyNames = 'items'
            ObjectName    = "$Label page"
        }

        if (-not (Test-ObjectProperties @propertyParams)) {
            return 0
        }

        if ($null -eq $CurrentPage.items) {
            return 0
        }

        return @($CurrentPage.items).Count
    }

    # Callers may pass endpoint filters in AddArgs. Strip any caller-provided
    # paging arguments so this helper owns the page window consistently.
    $baseArgs = Remove-QueryParameters -QueryString $AddArgs -QueryParams @('from', 'limit')

    $buildPageRequestArgs = {
        param(
            [int64]$CurrentOffset,
            [int64]$CurrentLimit,
            [bool]$IncludeOffset = $true
        )

        $requestArgs = $baseArgs

        if ($IncludeOffset) {
            $requestArgs = Join-QueryString -QueryString $requestArgs -Argument "from=$CurrentOffset"
        }

        $requestArgs = Join-QueryString -QueryString $requestArgs -Argument "limit=$CurrentLimit"

        return $requestArgs
    }

    # Some Action1 endpoints do not treat the first page the same when from=0 is
    # explicit. OmitInitialOffset lets those callers start with only limit=N.
    $currentRequestOffset = [int64]$Offset
    $initialRequestLimit = [int64]$Limit

    # The organizations endpoint currently returns an empty first page for
    # limit=1 without from. Ask for two rows first, then continue with limit=1.
    if ($OmitInitialOffset.IsPresent -and $initialRequestLimit -eq 1) {
        $initialRequestLimit = 2
        $message = "[$Label] Initial offset is omitted and limit is 1. "
        $message += 'Requesting limit=2 for the first page to avoid an empty response.'
        Write-Action1Debug $message
    }

    $requestArgs = & $buildPageRequestArgs `
        $currentRequestOffset `
        $initialRequestLimit `
        (-not $OmitInitialOffset.IsPresent)

    $page = Invoke-Action1ApiRequest -Method GET -Path $Path -Label $Label -AddArgs $requestArgs

    # Normal callers receive streamed items. AsPage callers receive page
    # envelopes so exporters can write each page incrementally.
    $writePagedOutput = {
        param(
            [object]$CurrentPage,
            [int]$CurrentPageNumber
        )

        if ($asPageOutput) {
            [PSCustomObject][ordered]@{
                Items      = @($CurrentPage.items)
                PageNumber = $CurrentPageNumber
                From       = Get-FirstPropertyValue -InputObject $CurrentPage -PropertyName 'from'
                Limit      = Get-FirstPropertyValue -InputObject $CurrentPage -PropertyName 'limit'
                TotalItems = Get-FirstPropertyValue -InputObject $CurrentPage -PropertyName 'total_items'
                NextPage   = Get-FirstPropertyValue -InputObject $CurrentPage -PropertyName 'next_page'
            }
            return
        }

        foreach ($item in @($CurrentPage.items)) {
            $item
        }
    }

    if ($null -eq $page) {
        Write-Action1Debug "[$Label] Page 1 returned null. Stopping pagination."
        return $null
    }

    $propertyParams = @{
        InputObject   = $page
        PropertyNames = 'items'
        ObjectName    = "$Label page"
    }

    if (-not (Test-ObjectProperties @propertyParams)) {
        Write-Action1Debug "[$Label] Response is not a paged result. Returning response as-is."
        $page
        return
    }

    $pageNumber = 1
    $itemCount = & $getPageItemCount $page

    Write-Action1Debug "[$Label] Processing page $pageNumber. Items: $itemCount"

    & $writePagedOutput $page $pageNumber

    # Prefer offset pagination when total_items is present. This covers
    # endpoints that expose collection size but omit next_page on some pages.
    Write-Action1Debug "[$Label] Trying total_items/from/limit pagination."

    $propertyParams = @{
        InputObject   = $page
        PropertyNames = 'total_items'
        ObjectName    = "$Label page"
    }

    $hasOffsetPagingProperties = Test-ObjectProperties @propertyParams

    if ($hasOffsetPagingProperties) {
        $totalItems = ConvertTo-Int64 -Value $page.total_items
        $responseFrom = ConvertTo-Int64 -Value $page.from
        $responseItemCount = & $getPageItemCount $page

        if ($null -eq $totalItems) {
            Write-Action1Debug "[$Label] total_items value '$($page.total_items)' is not numeric."
        }
        elseif ($responseItemCount -le 0) {
            # A zero-item first page can still expose next_page. Do not stop
            # until the next_page fallback below has had a chance to run.
            $message = "[$Label] Page 1 returned no items with total_items=$totalItems. "
            $message += 'Trying next_page pagination.'
            Write-Action1Debug $message
        }
        else {
            if ($null -eq $responseFrom -or $responseFrom -lt 0) {
                $responseFrom = $currentRequestOffset
            }

            $requestLimit = [int64]$Limit
            $nextOffset = $responseFrom + $responseItemCount

            while ($nextOffset -lt $totalItems) {
                $pageNumber++

                $message = "[$Label] Requesting page $pageNumber by offset. "
                $message += "from=$nextOffset; limit=$requestLimit; total_items=$totalItems"
                Write-Action1Debug $message

                $requestArgs = & $buildPageRequestArgs $nextOffset $requestLimit
                $currentRequestOffset = $nextOffset

                $page = Invoke-Action1ApiRequest -Method GET -Path $Path -Label $Label -AddArgs $requestArgs

                if ($null -eq $page) {
                    Write-Action1Debug "[$Label] Page $pageNumber returned null. Stopping pagination."
                    break
                }

                $propertyParams = @{
                    InputObject   = $page
                    PropertyNames = 'items'
                    ObjectName    = "$Label page"
                }

                if (-not (Test-ObjectProperties @propertyParams)) {
                    Write-Action1Debug "[$Label] Page $pageNumber does not contain items. Stopping pagination."
                    break
                }

                $itemCount = & $getPageItemCount $page

                Write-Action1Debug "[$Label] Processing page $pageNumber. Items: $itemCount"

                & $writePagedOutput $page $pageNumber

                # Re-read paging metadata from every response because some endpoints may
                # normalize the requested limit, update total_items between requests, or
                # return unexpected paging values. This also prevents infinite loops when
                # the returned offset does not advance.
                $previousOffset = $nextOffset

                $currentTotalItems = ConvertTo-Int64 -Value $page.total_items
                $currentFrom = ConvertTo-Int64 -Value $page.from
                $currentItemCount = & $getPageItemCount $page

                if ($null -ne $currentTotalItems) {
                    $totalItems = $currentTotalItems
                }

                if ($null -eq $currentFrom -or $currentFrom -lt 0) {
                    $currentFrom = $currentRequestOffset
                }

                if ($currentItemCount -le 0) {
                    Write-Action1Debug "[$Label] Page $pageNumber returned no items. Stopping pagination."
                    break
                }

                $nextOffset = $currentFrom + $currentItemCount

                if ($nextOffset -le $previousOffset) {
                    $message = "[$Label] Next offset did not advance. "
                    $message += "Previous offset: $previousOffset; "
                    $message += "next offset: $nextOffset. Stopping pagination."
                    Write-Action1Debug $message
                    break
                }
            }

            return
        }

        Write-Action1Debug "[$Label] Offset paging did not continue. Trying next_page pagination."
    }
    else {
        $message = "[$Label] total_items/from/limit paging properties are "
        $message += 'incomplete. Trying next_page pagination.'
        Write-Action1Debug $message
    }

    # Fall back to API-supplied next_page links when offset metadata is missing,
    # invalid, or cannot make progress from the first response.
    $propertyParams = @{
        InputObject   = $page
        PropertyNames = 'next_page'
        ObjectName    = "$Label page"
    }

    if (-not (Test-ObjectProperties @propertyParams)) {
        Write-Action1Debug "[$Label] Response does not contain next_page. Stopping pagination."
        return
    }

    $requestedNextPages = @{}

    while (-not [string]::IsNullOrWhiteSpace([string]$page.next_page)) {
        $nextPagePath = [string]$page.next_page

        if ($requestedNextPages.ContainsKey($nextPagePath)) {
            Write-Action1Debug "[$Label] next_page '$nextPagePath' was already requested. Stopping pagination."
            break
        }

        $requestedNextPages[$nextPagePath] = $true
        $pageNumber++

        Write-Action1Debug "[$Label] Requesting page $pageNumber by next_page..."

        $page = Invoke-Action1ApiRequest -Method GET -Path $nextPagePath -Label $Label

        if ($null -eq $page) {
            Write-Action1Debug "[$Label] Page $pageNumber returned null. Stopping pagination."
            break
        }

        $propertyParams = @{
            InputObject   = $page
            PropertyNames = 'items'
            ObjectName    = "$Label page"
        }

        if (-not (Test-ObjectProperties @propertyParams)) {
            Write-Action1Debug "[$Label] Page $pageNumber does not contain items. Stopping pagination."
            break
        }

        $itemCount = & $getPageItemCount $page

        Write-Action1Debug "[$Label] Processing page $pageNumber. Items: $itemCount"

        & $writePagedOutput $page $pageNumber
    }
}
