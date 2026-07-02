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

    $HasProperty = {
        param(
            [object]$InputObject,
            [string]$PropertyName
        )

        if ($null -eq $InputObject) {
            return $false
        }

        return ($InputObject.PSObject.Properties.Name -contains $PropertyName)
    }

    $ConvertToInt64 = {
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

    $GetPageItemCount = {
        param(
            [object]$CurrentPage
        )

        if ($null -eq $CurrentPage) {
            return 0
        }

        if (-not (& $HasProperty $CurrentPage 'items')) {
            return 0
        }

        if ($null -eq $CurrentPage.items) {
            return 0
        }

        return @($CurrentPage.items).Count
    }

    $RemovePagingArguments = {
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

    $BaseArgs = & $RemovePagingArguments $AddArgs

    $BuildPageRequestArgs = {
        param(
            [int64]$CurrentOffset,
            [int64]$CurrentLimit
        )

        $requestArgs = $BaseArgs
        $requestArgs = Join-QueryString -QueryString $requestArgs -Argument "from=$CurrentOffset"
        $requestArgs = Join-QueryString -QueryString $requestArgs -Argument "limit=$CurrentLimit"

        return $requestArgs
    }

    $RequestArgs = & $BuildPageRequestArgs $Offset $Limit

    $Page = Invoke-Action1ApiRequest -Method GET -Path $Path -Label $Label -AddArgs $RequestArgs

    if ($null -eq $Page) {
        Write-Action1Debug "[$Label] Page 1 returned null. Stopping pagination."
        return $null
    }

    if (-not (& $HasProperty $Page 'items')) {
        Write-Action1Debug "[$Label] Response is not a paged result. Returning response as-is."
        $Page
        return
    }

    $PageNumber = 1
    $ItemCount = & $GetPageItemCount $Page

    Write-Action1Debug "[$Label] Processing page $PageNumber. Items: $ItemCount"

    foreach ($Item in @($Page.items)) {
        $Item
    }

    if (& $HasProperty $Page 'next_page') {
        while (-not [string]::IsNullOrWhiteSpace([string]$Page.next_page)) {
            $PageNumber++

            Write-Action1Debug "[$Label] Requesting page $PageNumber by next_page..."

            $Page = Invoke-Action1ApiRequest -Method GET -Path $Page.next_page -Label $Label

            if ($null -eq $Page) {
                Write-Action1Debug "[$Label] Page $PageNumber returned null. Stopping pagination."
                break
            }

            if (-not (& $HasProperty $Page 'items')) {
                Write-Action1Debug "[$Label] Page $PageNumber does not contain items. Stopping pagination."
                break
            }

            $ItemCount = & $GetPageItemCount $Page

            Write-Action1Debug "[$Label] Processing page $PageNumber. Items: $ItemCount"

            foreach ($Item in @($Page.items)) {
                $Item
            }
        }

        return
    }

    Write-Action1Debug "[$Label] Response does not contain next_page. Trying total_items/from/limit pagination."

    if (
        -not (& $HasProperty $Page 'total_items') -or
        -not (& $HasProperty $Page 'limit') -or
        -not (& $HasProperty $Page 'from')
    ) {
        Write-Action1Debug "[$Label] total_items/from/limit paging properties are incomplete. Stopping pagination."
        return
    }

    $TotalItems = & $ConvertToInt64 $Page.total_items
    $ResponseLimit = & $ConvertToInt64 $Page.limit
    $ResponseFrom = & $ConvertToInt64 $Page.from

    if ($null -eq $TotalItems) {
        Write-Action1Debug "[$Label] total_items value '$($Page.total_items)' is not numeric. Stopping pagination."
        return
    }

    if ($null -eq $ResponseLimit -or $ResponseLimit -le 0) {
        Write-Action1Debug "[$Label] limit value '$($Page.limit)' is not a positive numeric value. Stopping pagination."
        return
    }

    if ($null -eq $ResponseFrom -or $ResponseFrom -lt 0) {
        Write-Action1Debug "[$Label] from value '$($Page.from)' is not a valid numeric value. Stopping pagination."
        return
    }

    $NextOffset = $ResponseFrom + $ResponseLimit

    while ($NextOffset -lt $TotalItems) {
        $PageNumber++

        Write-Action1Debug "[$Label] Requesting page $PageNumber by offset. from=$NextOffset; limit=$ResponseLimit; total_items=$TotalItems"

        $RequestArgs = & $BuildPageRequestArgs $NextOffset $ResponseLimit

        $Page = Invoke-Action1ApiRequest -Method GET -Path $Path -Label $Label -AddArgs $RequestArgs

        if ($null -eq $Page) {
            Write-Action1Debug "[$Label] Page $PageNumber returned null. Stopping pagination."
            break
        }

        if (-not (& $HasProperty $Page 'items')) {
            Write-Action1Debug "[$Label] Page $PageNumber does not contain items. Stopping pagination."
            break
        }

        $ItemCount = & $GetPageItemCount $Page

        Write-Action1Debug "[$Label] Processing page $PageNumber. Items: $ItemCount"

        foreach ($Item in @($Page.items)) {
            $Item
        }

        # Re-read paging metadata from every response because some endpoints may
        # normalize the requested limit, update total_items between requests, or
        # return unexpected paging values. This also prevents infinite loops when
        # the returned offset does not advance.
        $PreviousOffset = $NextOffset

        $CurrentTotalItems = & $ConvertToInt64 $Page.total_items
        $CurrentLimit = & $ConvertToInt64 $Page.limit
        $CurrentFrom = & $ConvertToInt64 $Page.from

        if ($null -ne $CurrentTotalItems) {
            $TotalItems = $CurrentTotalItems
        }

        if ($null -eq $CurrentLimit -or $CurrentLimit -le 0) {
            Write-Action1Debug "[$Label] Page $PageNumber returned invalid limit '$($Page.limit)'. Stopping pagination."
            break
        }

        if ($null -eq $CurrentFrom -or $CurrentFrom -lt 0) {
            Write-Action1Debug "[$Label] Page $PageNumber returned invalid from '$($Page.from)'. Stopping pagination."
            break
        }

        $ResponseLimit = $CurrentLimit
        $NextOffset = $CurrentFrom + $CurrentLimit

        if ($NextOffset -le $PreviousOffset) {
            Write-Action1Debug "[$Label] Next offset did not advance. Previous offset: $PreviousOffset; next offset: $NextOffset. Stopping pagination."
            break
        }
    }
}