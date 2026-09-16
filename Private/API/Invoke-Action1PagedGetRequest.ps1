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

# SIG # Begin signature block
# MII9MQYJKoZIhvcNAQcCoII9IjCCPR4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBgohronO44Sdjp
# o2aamxCR4FksNwGs0OVtHIz5nep0zaCCIfYwggXMMIIDtKADAgECAhBUmNLR1FsZ
# lUgTecgRwIeZMA0GCSqGSIb3DQEBDAUAMHcxCzAJBgNVBAYTAlVTMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xSDBGBgNVBAMTP01pY3Jvc29mdCBJZGVu
# dGl0eSBWZXJpZmljYXRpb24gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAy
# MDAeFw0yMDA0MTYxODM2MTZaFw00NTA0MTYxODQ0NDBaMHcxCzAJBgNVBAYTAlVT
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xSDBGBgNVBAMTP01pY3Jv
# c29mdCBJZGVudGl0eSBWZXJpZmljYXRpb24gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRo
# b3JpdHkgMjAyMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALORKgeD
# Bmf9np3gx8C3pOZCBH8Ppttf+9Va10Wg+3cL8IDzpm1aTXlT2KCGhFdFIMeiVPvH
# or+Kx24186IVxC9O40qFlkkN/76Z2BT2vCcH7kKbK/ULkgbk/WkTZaiRcvKYhOuD
# PQ7k13ESSCHLDe32R0m3m/nJxxe2hE//uKya13NnSYXjhr03QNAlhtTetcJtYmrV
# qXi8LW9J+eVsFBT9FMfTZRY33stuvF4pjf1imxUs1gXmuYkyM6Nix9fWUmcIxC70
# ViueC4fM7Ke0pqrrBc0ZV6U6CwQnHJFnni1iLS8evtrAIMsEGcoz+4m+mOJyoHI1
# vnnhnINv5G0Xb5DzPQCGdTiO0OBJmrvb0/gwytVXiGhNctO/bX9x2P29Da6SZEi3
# W295JrXNm5UhhNHvDzI9e1eM80UHTHzgXhgONXaLbZ7LNnSrBfjgc10yVpRnlyUK
# xjU9lJfnwUSLgP3B+PR0GeUw9gb7IVc+BhyLaxWGJ0l7gpPKWeh1R+g/OPTHU3mg
# trTiXFHvvV84wRPmeAyVWi7FQFkozA8kwOy6CXcjmTimthzax7ogttc32H83rwjj
# O3HbbnMbfZlysOSGM1l0tRYAe1BtxoYT2v3EOYI9JACaYNq6lMAFUSw0rFCZE4e7
# swWAsk0wAly4JoNdtGNz764jlU9gKL431VulAgMBAAGjVDBSMA4GA1UdDwEB/wQE
# AwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTIftJqhSobyhmYBAcnz1AQ
# T2ioojAQBgkrBgEEAYI3FQEEAwIBADANBgkqhkiG9w0BAQwFAAOCAgEAr2rd5hnn
# LZRDGU7L6VCVZKUDkQKL4jaAOxWiUsIWGbZqWl10QzD0m/9gdAmxIR6QFm3FJI9c
# Zohj9E/MffISTEAQiwGf2qnIrvKVG8+dBetJPnSgaFvlVixlHIJ+U9pW2UYXeZJF
# xBA2CFIpF8svpvJ+1Gkkih6PsHMNzBxKq7Kq7aeRYwFkIqgyuH4yKLNncy2RtNwx
# AQv3Rwqm8ddK7VZgxCwIo3tAsLx0J1KH1r6I3TeKiW5niB31yV2g/rarOoDXGpc8
# FzYiQR6sTdWD5jw4vU8w6VSp07YEwzJ2YbuwGMUrGLPAgNW3lbBeUU0i/OxYqujY
# lLSlLu2S3ucYfCFX3VVj979tzR/SpncocMfiWzpbCNJbTsgAlrPhgzavhgplXHT2
# 6ux6anSg8Evu75SjrFDyh+3XOjCDyft9V77l4/hByuVkrrOj7FjshZrM77nq81YY
# uVxzmq/FdxeDWds3GhhyVKVB0rYjdaNDmuV3fJZ5t0GNv+zcgKCf0Xd1WF81E+Al
# GmcLfc4l+gcK5GEh2NQc5QfGNpn0ltDGFf5Ozdeui53bFv0ExpK91IjmqaOqu/dk
# ODtfzAzQNb50GQOmxapMomE2gj4d8yu8l13bS3g7LfU772Aj6PXsCyM2la+YZr9T
# 03u4aUoqlmZpxJTG9F9urJh4iIAGXKKy7aIwggaoMIIEkKADAgECAhMzAAYrsCUD
# ok6FalIzAAAABiuwMA0GCSqGSIb3DQEBDAUAMFoxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDUyBFT0MgQ0EgMDMwHhcNMjYwOTE0MTk1MjM0WhcNMjYwOTE3
# MTk1MjM0WjBrMQswCQYDVQQGEwJVUzEOMAwGA1UECBMFVGV4YXMxEDAOBgNVBAcT
# B0hvdXN0b24xHDAaBgNVBAoTE0FjdGlvbjEgQ29ycG9yYXRpb24xHDAaBgNVBAMT
# E0FjdGlvbjEgQ29ycG9yYXRpb24wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQCVI8Jq/ow2Mfvld+sBPNm1XkkSASORmRsgRMM7VdVAZX7sBWeUfg7dWBw3
# Adg08um3LEl0n/KZB7o2c8FkhkKqfP0ZpamKBjESpumgA9NIlyC7YLfhYUsFjDEQ
# W8cdXzkOXaT+353m8dcHUDOm80jxl5ElAlOeGW8LkJq5VTrCeRzZDGhZZ3ZSfphG
# t1/eUxcDtOQc5klOlmJ2EkyPKNY9TlhyMRXdAqUKL/KCvQz+QOZiN3h7vus4W0JZ
# afpepyBzdS5BElXJP3PVA7Xs4NMcAYYbFeenMZLfSRlxcvZgGhWtSRDmbiq4di9+
# EkdCIR2FwTh+pxq4ibU46FquLPOk7qiCSmJV5kK2+kYyBac4WyrhIPQjoAv6KtNL
# Ryim2hUqUiwpB16lvLSP0OPlGyNsDdxlqRNJRiWmsBDjvmkPO4qdttKsly1vyWbH
# Bp4XIJOtsklhLfXrh0V9HD05AUay/s5bq+cqfXYfuARsgGC9y7WSc+wwyv/Qd7th
# l6TLrP0CAwEAAaOCAdQwggHQMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeA
# MDsGA1UdJQQ0MDIGCisGAQQBgjdhAQAGCCsGAQUFBwMDBhorBgEEAYI3YYTGyjWC
# 84fIeoPTzfIboMPaLTAdBgNVHQ4EFgQUP4pA7Ia3qR7nLmGl0RN4bApDmlkwHwYD
# VR0jBBgwFoAUa16lNMMFxWJKIVqOq3NgYtSsY4UwZwYDVR0fBGAwXjBcoFqgWIZW
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# SUQlMjBWZXJpZmllZCUyMENTJTIwRU9DJTIwQ0ElMjAwMy5jcmwwdAYIKwYBBQUH
# AQEEaDBmMGQGCCsGAQUFBzAChlhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUyMEVPQyUy
# MENBJTIwMDMuY3J0MFQGA1UdIARNMEswSQYEVR0gADBBMD8GCCsGAQUFBwIBFjNo
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5o
# dG0wDQYJKoZIhvcNAQEMBQADggIBAJXkO183cDuRZfQ+fpONLNL3IAu/iRi5ltCP
# lNY6I/jh5z4M7LCgRMwgbH0ivvvzeZXFnO4d21QQITTMtlRj+ywsdwKHIdx9/aCh
# 05CM/vKZWnyvFj+uZWFJNT5mcgemiGGGtyk6p1vOwPHfUg9jTVvGvjC+97QVCD2w
# lz7/qqE41GExV+PSxkCURxvyojpMyf+aLF5FvEUFzS/R0Ogdg0VHLOK2W4BAvVgw
# LAK+gH47JI0clEh/msUfK7QLY7nkOKOhjYctCZKnWe0CSBl/15h3JP8Jr46gAvQr
# DixOC9II2ndbKRZig/H0hJSOr6loKpzJkyVE3gM74/Mf6LY2CHve0YZPQPqaaCAf
# Xi5ufF1dYAU7NYC2pu8vg8qFHhmDPi0QkaVsvbU9K+DH+m4Jhlu1Dfpk+wjO9H6K
# 34vC5F7+LTuc17IcrQ8bAoswm6uhLh6YtZzEy9klCyvOl/7ZIa6n85q18kVWz5ZN
# tGwzwK260QB5IWWqsDGPOFprAIslHQxibYYGMUKLuJ80WoPCG71VcWi6ymzi4gss
# PkzjhmpjRDz8liAqkwDQq8w4kC0FsX2C0hprO9d1pb6w81MNVoVJBIbfUqA62G3w
# Pub5+FuJhzjuz+F712EhwQoznmIod+T+DgcWJCx4m6sgvaJcCGb0nEWjeLB5PQ4u
# 2+vhKypjMIIGqDCCBJCgAwIBAgITMwAGK7AlA6JOhWpSMwAAAAYrsDANBgkqhkiG
# 9w0BAQwFADBaMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgSUQgVmVyaWZpZWQgQ1MgRU9DIENB
# IDAzMB4XDTI2MDkxNDE5NTIzNFoXDTI2MDkxNzE5NTIzNFowazELMAkGA1UEBhMC
# VVMxDjAMBgNVBAgTBVRleGFzMRAwDgYDVQQHEwdIb3VzdG9uMRwwGgYDVQQKExNB
# Y3Rpb24xIENvcnBvcmF0aW9uMRwwGgYDVQQDExNBY3Rpb24xIENvcnBvcmF0aW9u
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAlSPCav6MNjH75XfrATzZ
# tV5JEgEjkZkbIETDO1XVQGV+7AVnlH4O3VgcNwHYNPLptyxJdJ/ymQe6NnPBZIZC
# qnz9GaWpigYxEqbpoAPTSJcgu2C34WFLBYwxEFvHHV85Dl2k/t+d5vHXB1AzpvNI
# 8ZeRJQJTnhlvC5CauVU6wnkc2QxoWWd2Un6YRrdf3lMXA7TkHOZJTpZidhJMjyjW
# PU5YcjEV3QKlCi/ygr0M/kDmYjd4e77rOFtCWWn6Xqcgc3UuQRJVyT9z1QO17ODT
# HAGGGxXnpzGS30kZcXL2YBoVrUkQ5m4quHYvfhJHQiEdhcE4fqcauIm1OOharizz
# pO6ogkpiVeZCtvpGMgWnOFsq4SD0I6AL+irTS0coptoVKlIsKQdepby0j9Dj5Rsj
# bA3cZakTSUYlprAQ475pDzuKnbbSrJctb8lmxwaeFyCTrbJJYS3164dFfRw9OQFG
# sv7OW6vnKn12H7gEbIBgvcu1knPsMMr/0He7YZeky6z9AgMBAAGjggHUMIIB0DAM
# BgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDA7BgNVHSUENDAyBgorBgEEAYI3
# YQEABggrBgEFBQcDAwYaKwYBBAGCN2GExso1gvOHyHqD083yG6DD2i0wHQYDVR0O
# BBYEFD+KQOyGt6ke5y5hpdETeGwKQ5pZMB8GA1UdIwQYMBaAFGtepTTDBcViSiFa
# jqtzYGLUrGOFMGcGA1UdHwRgMF4wXKBaoFiGVmh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUy
# MEVPQyUyMENBJTIwMDMuY3JsMHQGCCsGAQUFBwEBBGgwZjBkBggrBgEFBQcwAoZY
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQl
# MjBJRCUyMFZlcmlmaWVkJTIwQ1MlMjBFT0MlMjBDQSUyMDAzLmNydDBUBgNVHSAE
# TTBLMEkGBFUdIAAwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMA0GCSqGSIb3DQEBDAUAA4IC
# AQCV5DtfN3A7kWX0Pn6TjSzS9yALv4kYuZbQj5TWOiP44ec+DOywoETMIGx9Ir77
# 83mVxZzuHdtUECE0zLZUY/ssLHcChyHcff2godOQjP7ymVp8rxY/rmVhSTU+ZnIH
# pohhhrcpOqdbzsDx31IPY01bxr4wvve0FQg9sJc+/6qhONRhMVfj0sZAlEcb8qI6
# TMn/mixeRbxFBc0v0dDoHYNFRyzitluAQL1YMCwCvoB+OySNHJRIf5rFHyu0C2O5
# 5DijoY2HLQmSp1ntAkgZf9eYdyT/Ca+OoAL0Kw4sTgvSCNp3WykWYoPx9ISUjq+p
# aCqcyZMlRN4DO+PzH+i2Ngh73tGGT0D6mmggH14ubnxdXWAFOzWAtqbvL4PKhR4Z
# gz4tEJGlbL21PSvgx/puCYZbtQ36ZPsIzvR+it+LwuRe/i07nNeyHK0PGwKLMJur
# oS4emLWcxMvZJQsrzpf+2SGup/OatfJFVs+WTbRsM8CtutEAeSFlqrAxjzhaawCL
# JR0MYm2GBjFCi7ifNFqDwhu9VXFousps4uILLD5M44ZqY0Q8/JYgKpMA0KvMOJAt
# BbF9gtIaazvXdaW+sPNTDVaFSQSG31KgOtht8D7m+fhbiYc47s/he9dhIcEKM55i
# KHfk/g4HFiQseJurIL2iXAhm9JxFo3iweT0OLtvr4SsqYzCCBygwggUQoAMCAQIC
# EzMAAAAVBT5uGY6TKdkAAAAAABUwDQYJKoZIhvcNAQEMBQAwYzELMAkGA1UEBhMC
# VVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE0MDIGA1UEAxMrTWlj
# cm9zb2Z0IElEIFZlcmlmaWVkIENvZGUgU2lnbmluZyBQQ0EgMjAyMTAeFw0yNjAz
# MjYxODExMjhaFw0zMTAzMjYxODExMjhaMFoxCzAJBgNVBAYTAlVTMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJRCBW
# ZXJpZmllZCBDUyBFT0MgQ0EgMDMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQDg9Ms9AqovDnMePvMOe+KybhCd8+lokzYORlS3kBVXseecbyGwBcsenlm5
# bLtMGPjiIFLzBQF+ghlVV/U29q5GcdeEEBCHTTGhL2koIrLc4UrliMRcbv9mOMtR
# /l7/xAmv0Fx4BJHn1dHt37fvrBqXmKjKfGf5DpyO/+hnV7TEreMtS19iO+bjZ/9H
# npg3PCk0e7YSbRTFkx97FZwRWpC4s3NepRfRXQh/WMAj7JmsYeVZohi4TF5yW2JM
# rJZqwHcyzJZYtD2Hlno5ZEJkdiZcEaxHOobmwO06Z1J9c23ps9PGIhGaq1sKLEAz
# 9Doc5rLkYWGteDrscKhAp2kIc/oYlH9Ij6BkOqqgWINEkEtC8ZNG1Mak+h3o65aj
# 0iQKmdxW7IZaHO5cuyoMi+KtYfXeIIg3sVIbS2EL8kUtsDGdEqNqAq/isqTi1jXq
# Le6iKp1ni1SPdvPW9G03CTsYF68b/yuIQRwbdoBCXemMNJCS0dorCRY4b2WAAy4n
# g7SANcEgrBgZf535+QfLU5hGzrKjIpbMabauWb5FKWUKkMsPcXFkXRWO4noKPm4K
# WlFypqOpbJ/KONVReIlxHQRegAOBzIhRB7gr9IDQ1sc2MgOgQ+xVGW4oq4HD0mfA
# iwiyLskZrkaQ7JoanYjBNcR9RS26YxAVbcBtLitFTzCIEg5ZdQIDAQABo4IB3DCC
# AdgwDgYDVR0PAQH/BAQDAgGGMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRr
# XqU0wwXFYkohWo6rc2Bi1KxjhTBUBgNVHSAETTBLMEkGBFUdIAAwQTA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9z
# aXRvcnkuaHRtMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMBIGA1UdEwEB/wQI
# MAYBAf8CAQAwHwYDVR0jBBgwFoAU2UEpsA8PY2zvadf1zSmepEhqMOYwcAYDVR0f
# BGkwZzBloGOgYYZfaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwv
# TWljcm9zb2Z0JTIwSUQlMjBWZXJpZmllZCUyMENvZGUlMjBTaWduaW5nJTIwUENB
# JTIwMjAyMS5jcmwwfQYIKwYBBQUHAQEEcTBvMG0GCCsGAQUFBzAChmFodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIw
# VmVyaWZpZWQlMjBDb2RlJTIwU2lnbmluZyUyMFBDQSUyMDIwMjEuY3J0MA0GCSqG
# SIb3DQEBDAUAA4ICAQBdbiI8zwXLX8glJEh/8Q22UMCUhWBO46Z9FPhwOR3mdlqR
# VLkYOon/MczUwrjDhx3X99SPH5PSflkGoTvnO9ZWHM5YFVYpO7NYuB+mfVSGAGZw
# iGOASWk0i2B7vn9nElJJmoiXxugfH5YdBsrUgTt0AFNXkzmqTgk+S1Hxb1u/0HCq
# EHVZPk2A/6eJXYbtpRM5Fcz00jisUl9BRZgSebODV85bBzOveqyC3f0PnHCxRJNh
# Mb8xP/sB/VI7pf2rheSV7zqUSv8vn/fIMblXeaVIlpqoq8SP9BJMjE/CoVXJxnkZ
# QRM1Fa7kN9yztvReOhxSgPgpZx/Xl/jkwyEFVJTBfBp3sTgfIc/pmqv2ehtakL2A
# Ej78EmOPQohxJT3wyX+P78GA25tLpAvzj3RMMHd8z18ZuuVi+60MAzGpOASH1L8N
# lr3fZRZnQO+pyye2DCvYmHaIfdUgYJqn7noxxGVv89+RaETh1tgCDvwNpFCSG7vl
# 5A4ako+2fx409r9TWjXC7Oif1IQ5ZJzB4Rf8GvBiHYjvMmHpledp1FGRLdSRFVpC
# 3/OKpZY6avIqZp7+8pP/WQP903DdgrvAT6W4xPOBxXPa4tGksN3SuqJaiFYHSNye
# Bufn8iseujW4IbBSbHD4BPqbF3qZ+7nG9d/d/G2/Lx4kH9cCmBfmsZdSkHmukDCC
# B54wggWGoAMCAQICEzMAAAAHh6M0o3uljhwAAAAAAAcwDQYJKoZIhvcNAQEMBQAw
# dzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjFI
# MEYGA1UEAxM/TWljcm9zb2Z0IElkZW50aXR5IFZlcmlmaWNhdGlvbiBSb290IENl
# cnRpZmljYXRlIEF1dGhvcml0eSAyMDIwMB4XDTIxMDQwMTIwMDUyMFoXDTM2MDQw
# MTIwMTUyMFowYzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjE0MDIGA1UEAxMrTWljcm9zb2Z0IElEIFZlcmlmaWVkIENvZGUgU2ln
# bmluZyBQQ0EgMjAyMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALLw
# wK8ZiCji3VR6TElsaQhVCbRS/3pK+MHrJSj3Zxd3KU3rlfL3qrZilYKJNqztA9OQ
# acr1AwoNcHbKBLbsQAhBnIB34zxf52bDpIO3NJlfIaTE/xrweLoQ71lzCHkD7A4A
# s1Bs076Iu+mA6cQzsYYH/Cbl1icwQ6C65rU4V9NQhNUwgrx9rGQ//h890Q8JdjLL
# w0nV+ayQ2Fbkd242o9kH82RZsH3HEyqjAB5a8+Ae2nPIPc8sZU6ZE7iRrRZywRmr
# KDp5+TcmJX9MRff241UaOBs4NmHOyke8oU1TYrkxh+YeHgfWo5tTgkoSMoayqoDp
# HOLJs+qG8Tvh8SnifW2Jj3+ii11TS8/FGngEaNAWrbyfNrC69oKpRQXY9bGH6jn9
# NEJv9weFxhTwyvx9OJLXmRGbAUXN1U9nf4lXezky6Uh/cgjkVd6CGUAf0K+Jw+GE
# /5VpIVbcNr9rNE50Sbmy/4RTCEGvOq3GhjITbCa4crCzTTHgYYjHs1NbOc6brH+e
# KpWLtr+bGecy9CrwQyx7S/BfYJ+ozst7+yZtG2wR461uckFu0t+gCwLdN0A6cFtS
# RtR8bvxVFyWwTtgMMFRuBa3vmUOTnfKLsLefRaQcVTgRnzeLzdpt32cdYKp+dhr2
# ogc+qM6K4CBI5/j4VFyC4QFeUP2YAidLtvpXRRo3AgMBAAGjggI1MIICMTAOBgNV
# HQ8BAf8EBAMCAYYwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNlBKbAPD2Ns
# 72nX9c0pnqRIajDmMFQGA1UdIARNMEswSQYEVR0gADBBMD8GCCsGAQUFBwIBFjNo
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5o
# dG0wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDwYDVR0TAQH/BAUwAwEB/zAf
# BgNVHSMEGDAWgBTIftJqhSobyhmYBAcnz1AQT2ioojCBhAYDVR0fBH0wezB5oHeg
# dYZzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0
# JTIwSWRlbnRpdHklMjBWZXJpZmljYXRpb24lMjBSb290JTIwQ2VydGlmaWNhdGUl
# MjBBdXRob3JpdHklMjAyMDIwLmNybDCBwwYIKwYBBQUHAQEEgbYwgbMwgYEGCCsG
# AQUFBzAChnVodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01p
# Y3Jvc29mdCUyMElkZW50aXR5JTIwVmVyaWZpY2F0aW9uJTIwUm9vdCUyMENlcnRp
# ZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAyMC5jcnQwLQYIKwYBBQUHMAGGIWh0dHA6
# Ly9vbmVvY3NwLm1pY3Jvc29mdC5jb20vb2NzcDANBgkqhkiG9w0BAQwFAAOCAgEA
# fyUqnv7Uq+rdZgrbVyNMul5skONbhls5fccPlmIbzi+OwVdPQ4H55v7VOInnmezQ
# EeW4LqK0wja+fBznANbXLB0KrdMCbHQpbLvG6UA/Xv2pfpVIE1CRFfNF4XKO8XYE
# a3oW8oVH+KZHgIQRIwAbyFKQ9iyj4aOWeAzwk+f9E5StNp5T8FG7/VEURIVWArbA
# zPt9ThVN3w1fAZkF7+YU9kbq1bCR2YD+MtunSQ1Rft6XG7b4e0ejRA7mB2IoX5hN
# h3UEauY0byxNRG+fT2MCEhQl9g2i2fs6VOG19CNep7SquKaBjhWmirYyANb0RJSL
# WjinMLXNOAga10n8i9jqeprzSMU5ODmrMCJE12xS/NWShg/tuLjAsKP6SzYZ+1Ry
# 358ZTFcx0FS/mx2vSoU8s8HRvy+rnXqyUJ9HBqS0DErVLjQwK8VtsBdekBmdTbQV
# oCgPCqr+PDPB3xajYnzevs7eidBsM71PINK2BoE2UfMwxCCX3mccFgx6UsQeRSdV
# VVNSyALQe6PT12418xon2iDGE81OGCreLzDcMAZnrUAx4XQLUz6ZTl65yPUiOh3k
# 7Yww94lDf+8oG2oZmDh5O1Qe38E+M3vhKwmzIeoB1dVLlz4i3IpaDcR+iuGjH2Td
# aC1ZOmBXiCRKJLj4DT2uhJ04ji+tHD6n58vhavFIrmcxghqRMIIajQIBATBxMFox
# CzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzAp
# BgNVBAMTIk1pY3Jvc29mdCBJRCBWZXJpZmllZCBDUyBFT0MgQ0EgMDMCEzMABiuw
# JQOiToVqUjMAAAAGK7AwDQYJYIZIAWUDBAIBBQCgXjAQBgorBgEEAYI3AgEMMQIw
# ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAvBgkqhkiG9w0BCQQxIgQglEee
# Cgi+DxeseHr+wK4AeuEV1PKxWG/o97NcXK7FUw4wDQYJKoZIhvcNAQEBBQAEggGA
# W6zpSBY3ptQIwJFs7Os5N4XzXCIoqYuu+oa8uTtiFInR9yzv8ogo0fGep64vx1fQ
# mi0EHgg7JqG8LMN2ZWNuVkCwOdwhr1B6yt7IxWsO7ivRyakcPPg5YCAPhY46JVX3
# GSgVLrvfWuJEv8Rd/uA6QSHm9uth6sQi1HS7++SNcXsNEv4FSC/IqJ+6bUo/0APx
# nstLgbDSiNDi8wlnuucjgLSwNPhQ/Xf/RI5dfP6WC94PmB5zvzEDkN9GvnWx/1AK
# BPvrUQZ9eH13ZRWm5eelwtk0Jo8ecFUVUisvbq/kBpqoVeQ3BKbj7vJlWfncrqyf
# /rSmrDENO1lmooXn6NFEV9jUmg0RN+ppeLcX1XhGzqMs/1ojPHfs7nDAX4hJqYXt
# DY6kzZruNp/mXqlcYLjlO6hOUvYGcWTWNGTGwvA+ID6ePd3hN1xGUZmwuvXokfk2
# UysMD0AB/Qhg7bMBLbd7CuVKwwBss9VNx4D8v7mW+t/qJZLnRV5Qk8ZJIpQsBwni
# oYIYETCCGA0GCisGAQQBgjcDAwExghf9MIIX+QYJKoZIhvcNAQcCoIIX6jCCF+YC
# AQMxDzANBglghkgBZQMEAgEFADCCAWIGCyqGSIb3DQEJEAEEoIIBUQSCAU0wggFJ
# AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIP0XKur9sBRaoMbAzCK5
# 3UxdgP4J68Bbms52UW0nYmEyAgZqqUsMyZEYEzIwMjYwOTE2MTAzNDU1LjQyNlow
# BIACAfSggeGkgd4wgdsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNV
# BAsTHm5TaGllbGQgVFNTIEVTTjo3QTAwLTA1RTAtRDk0NzE1MDMGA1UEAxMsTWlj
# cm9zb2Z0IFB1YmxpYyBSU0EgVGltZSBTdGFtcGluZyBBdXRob3JpdHmggg8hMIIH
# gjCCBWqgAwIBAgITMwAAAAXlzw//Zi7JhwAAAAAABTANBgkqhkiG9w0BAQwFADB3
# MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMUgw
# RgYDVQQDEz9NaWNyb3NvZnQgSWRlbnRpdHkgVmVyaWZpY2F0aW9uIFJvb3QgQ2Vy
# dGlmaWNhdGUgQXV0aG9yaXR5IDIwMjAwHhcNMjAxMTE5MjAzMjMxWhcNMzUxMTE5
# MjA0MjMxWjBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBp
# bmcgQ0EgMjAyMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJ5851Jj
# /eDFnwV9Y7UGIqMcHtfnlzPREwW9ZUZHd5HBXXBvf7KrQ5cMSqFSHGqg2/qJhYqO
# QxwuEQXG8kB41wsDJP5d0zmLYKAY8Zxv3lYkuLDsfMuIEqvGYOPURAH+Ybl4SJEE
# Snt0MbPEoKdNihwM5xGv0rGofJ1qOYSTNcc55EbBT7uq3wx3mXhtVmtcCEr5ZKTk
# KKE1CxZvNPWdGWJUPC6e4uRfWHIhZcgCsJ+sozf5EeH5KrlFnxpjKKTavwfFP6Xa
# GZGWUG8TZaiTogRoAlqcevbiqioUz1Yt4FRK53P6ovnUfANjIgM9JDdJ4e0qiDRm
# 5sOTiEQtBLGd9Vhd1MadxoGcHrRCsS5rO9yhv2fjJHrmlQ0EIXmp4DhDBieKUGR+
# eZ4CNE3ctW4uvSDQVeSp9h1SaPV8UWEfyTxgGjOsRpeexIveR1MPTVf7gt8hY64X
# NPO6iyUGsEgt8c2PxF87E+CO7A28TpjNq5eLiiunhKbq0XbjkNoU5JhtYUrlmAbp
# xRjb9tSreDdtACpm3rkpxp7AQndnI0Shu/fk1/rE3oWsDqMX3jjv40e8KN5YsJBn
# czyWB4JyeeFMW3JBfdeAKhzohFe8U5w9WuvcP1E8cIxLoKSDzCCBOu0hWdjzKNu8
# Y5SwB1lt5dQhABYyzR3dxEO/T1K/BVF3rV69AgMBAAGjggIbMIICFzAOBgNVHQ8B
# Af8EBAMCAYYwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFGtpKDo1L0hjQM97
# 2K9J6T7ZPdshMFQGA1UdIARNMEswSQYEVR0gADBBMD8GCCsGAQUFBwIBFjNodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0w
# EwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEw
# DwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTIftJqhSobyhmYBAcnz1AQT2io
# ojCBhAYDVR0fBH0wezB5oHegdYZzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jcmwvTWljcm9zb2Z0JTIwSWRlbnRpdHklMjBWZXJpZmljYXRpb24lMjBS
# b290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDIwLmNybDCBlAYIKwYB
# BQUHAQEEgYcwgYQwgYEGCCsGAQUFBzAChnVodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMElkZW50aXR5JTIwVmVyaWZpY2F0
# aW9uJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAyMC5jcnQw
# DQYJKoZIhvcNAQEMBQADggIBAF+Idsd+bbVaFXXnTHho+k7h2ESZJRWluLE0Oa/p
# O+4ge/XEizXvhs0Y7+KVYyb4nHlugBesnFqBGEdC2IWmtKMyS1OWIviwpnK3aL5J
# edwzbeBF7POyg6IGG/XhhJ3UqWeWTO+Czb1c2NP5zyEh89F72u9UIw+IfvM9lzDm
# c2O2END7MPnrcjWdQnrLn1Ntday7JSyrDvBdmgbNnCKNZPmhzoa8PccOiQljjTW6
# GePe5sGFuRHzdFt8y+bN2neF7Zu8hTO1I64XNGqst8S+w+RUdie8fXC1jKu3m9KG
# IqF4aldrYBamyh3g4nJPj/LR2CBaLyD+2BuGZCVmoNR/dSpRCxlot0i79dKOChmo
# ONqbMI8m04uLaEHAv4qwKHQ1vBzbV/nG89LDKbRSSvijmwJwxRxLLpMQ/u4xXxFf
# R4f/gksSkbJp7oqLwliDm/h+w0aJ/U5ccnYhYb7vPKNMN+SZDWycU5ODIRfyoGl5
# 9BsXR/HpRGtiJquOYGmvA/pk5vC1lcnbeMrcWD/26ozePQ/TWfNXKBOmkFpvPE8C
# H+EeGGWzqTCjdAsno2jzTeNSxlx3glDGJgcdz5D/AAxw9Sdgq/+rY7jjgs7X6fqP
# TXPmaCAJKVHAP19oEjJIBwD1LyHbaEgBxFCogYSOiUIr0Xqcr1nJfiWG2GwYe6Zo
# AF1bMIIHlzCCBX+gAwIBAgITMwAAAFhlzes/odf80gAAAAAAWDANBgkqhkiG9w0B
# AQwFADBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcg
# Q0EgMjAyMDAeFw0yNTEwMjMyMDQ2NTVaFw0yNjEwMjIyMDQ2NTVaMIHbMQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3Nv
# ZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046
# N0EwMC0wNUUwLUQ5NDcxNTAzBgNVBAMTLE1pY3Jvc29mdCBQdWJsaWMgUlNBIFRp
# bWUgU3RhbXBpbmcgQXV0aG9yaXR5MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAnXg0pHaQ7PVAlln+HZZrJFcLoKbekhW1yL+QNBUgFFUsjZIKaqqN4oIJ
# sJM3ps0rJNSO7ndCNRuZDX2Wgur3Ak77eXrloBXqZmO6ZVXeDNRCLldW4A0/Nfjz
# J7XXkdEhjr81ghXEpR7zC+wbaNN+sPSxzLAZBeibDFP7Xws5wX0ZtIsN1a2+Xq5b
# vWp3kRMytwskTjunRgeLZL/tBp237JVdRPFAQ9jYRKpCqUBo/v1xjBLRCV3PalKj
# nGfb3MN4U7jVyqifFHShcnW5CERRoBmUa6sygDzFSr8e3g93TPNLFUivUE0GmLfb
# X5ceD1Gt1FcZ6x/JLVATzk5+BWHbMxwJIVkVPTqSSMjQ6KTKdcnq3pH0c4AFJp/g
# lvcpq0U9fzZIjJGGvdpishlRl77RQtUhSjxHvCn3LC/xqQQwOHSQDsGh6NX2D0Rf
# sSyEtTAByAae+2w1HByTDTcmlTNLEuQLeCj1gNBdIWj0WOYyDtjjQ/8iTWY6ey1v
# b9qHljIj5HgIndT5P9MYk2Vg2e7hKUZNBNbA/hsgBsuoZ+IX89WvjEN9abF91S4O
# JVuinmKsLO/MLbnl7ikuD0dN6oA0YewyDQncs12sM9HOtu72QA/TZlefvW8r9xtM
# XAYoQlcGjsk8W4Uc7cfqVqbIPjdoc8ZxBzLcXcVyP4p5cyLwvkMCAwEAAaOCAcsw
# ggHHMB0GA1UdDgQWBBRyjU3Fer4VxXJ+hjPcRJnxnRIJsDAfBgNVHSMEGDAWgBRr
# aSg6NS9IY0DPe9ivSek+2T3bITBsBgNVHR8EZTBjMGGgX6BdhltodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBQdWJsaWMlMjBS
# U0ElMjBUaW1lc3RhbXBpbmclMjBDQSUyMDIwMjAuY3JsMHkGCCsGAQUFBwEBBG0w
# azBpBggrBgEFBQcwAoZdaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# ZXJ0cy9NaWNyb3NvZnQlMjBQdWJsaWMlMjBSU0ElMjBUaW1lc3RhbXBpbmclMjBD
# QSUyMDIwMjAuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUH
# AwgwDgYDVR0PAQH/BAQDAgeAMGYGA1UdIARfMF0wUQYMKwYBBAGCN0yDfQEBMEEw
# PwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9j
# cy9SZXBvc2l0b3J5Lmh0bTAIBgZngQwBBAIwDQYJKoZIhvcNAQEMBQADggIBAHvr
# xIiVF1iHcXvxrJTCD8eOtbPUbK9x+Lz70iYehh+G0UoOMcMf04QD6tQPTeZ5HhGE
# Tkcn0raDJ5NpfbRBuKEH31rxbZK97o12KRDNJ3Nu4ePaUIpH/TcWz8PLVOCECywS
# xbEgEG20kyydGc46c591tXzpfkJDckjoYrypaerdeQLRQH9LaoTYZfdAzMo+Dy0O
# 1DzFJkF5YnsmAM8lt9r1NtXdFjdbFMCbV5dau64mV22s186A8Umi+l239+Ue0cbJ
# QIykWhIlhhWhxQgoksqHz7kp2GFZAAeySTmIOQOWyXOA8JA8TISJyn3JDOgStv58
# 3P3V0QSALT6JXDCW26FV208VGJMzkv0S22iOTZJ/oamTpk8RzD8oWT8pfbe1q/k/
# bxPiXYRbzps96a5YOko7n0Vdo61DOJhL/mhk01Y348gq6vhG/VTcdGHh1rCkwOM0
# 5B35AZZq9AtPpfRzJinrHzzGRx+r6fD3ccYMPMMX/Nwd2irzrph172fQcSf1fMwv
# wIhmfH4GWJJ+mf1HA6uXoAOVByckguXvlj8gPi7T2ES6RU8+QssfqTNTJKjsBheW
# KWv2W4ESVen2L7lCz7i79FhA+0kp0yXJnYwdzWS0ovTINULINmzVyMcSUm5WuVf8
# YZ33cAud2Opr6N1+RuLZDavDvjiehlI5dH+GEy56MYIHQzCCBz8CAQEweDBhMQsw
# CQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYD
# VQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMAIT
# MwAAAFhlzes/odf80gAAAAAAWDANBglghkgBZQMEAgEFAKCCBJwwEQYLKoZIhvcN
# AQkQAg8xAgUAMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0B
# CQUxDxcNMjYwOTE2MTAzNDU1WjAvBgkqhkiG9w0BCQQxIgQgWjtCgJcUfmYcJxNx
# 05U5fH3hP6bJuShawhlzfxKhfPIwgbkGCyqGSIb3DQEJEAIvMYGpMIGmMIGjMIGg
# BCDFIlS7sgfQ+wAo1cWbWz+WN69VBds58hbran919aLocTB8MGWkYzBhMQswCQYD
# VQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQD
# EylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMAITMwAA
# AFhlzes/odf80gAAAAAAWDCCA14GCyqGSIb3DQEJEAISMYIDTTCCA0mhggNFMIID
# QTCCAikCAQEwggEJoYHhpIHeMIHbMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046N0EwMC0wNUUwLUQ5NDcxNTAzBgNV
# BAMTLE1pY3Jvc29mdCBQdWJsaWMgUlNBIFRpbWUgU3RhbXBpbmcgQXV0aG9yaXR5
# oiMKAQEwBwYFKw4DAhoDFQCdZHkb26ercF2O62vCdZUfUSvEXKBnMGWkYzBhMQsw
# CQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYD
# VQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMDAN
# BgkqhkiG9w0BAQsFAAIFAO5Uck8wIhgPMjAyNjA5MTYwMTQxMzVaGA8yMDI2MDkx
# NzAxNDEzNVowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA7lRyTwIBADAHAgEAAgId
# AjAHAgEAAgISXjAKAgUA7lXDzwIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEE
# AYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBCwUAA4IB
# AQCelJvFk43XKr7ByniElQD0mLk77tWTRRPv+ZhqF5JIfKeTTPqfM5C0Ds9Eh4UR
# kr8ngWesp3TK/APV9KO6NyEJUETeP7n0eKcKYrcWl1vNTwbcawIYX7PyK66oUlRa
# zkQG5lcbtqLnCyPBqrDLkVyiW4bywqyfFuaSlb2OywN+ws/haPe6xkH6sqFneg7U
# d2Ysdmp5qjH5c0erqoAgFWTMOfXMjJtLjR5tUqZC3Zcm/8ps/sC7RFdORQnXkjQ/
# 1dTn40wG4h/txGDO7Us9aGgpJguFoceUR2AH2hfyxJEcmkdQncgKZcVS3fEkVDom
# vxGaq3uJTimbBK5H9R2mtygrMA0GCSqGSIb3DQEBAQUABIICAHXD/B0JaQPDpg0W
# jW4wVUau7A3/IfBtFEzxZc/HSinshg3w2hg3QHa2ha+p1ZrcHLMD8nR0vlgBg70E
# B8gtRzx+mmeR0/ijWrRvDWR2xkqzCsV8DQVJI+UfKy5KXgpuR6x01G1YCDrcn01Y
# DFl6gCssSx+pE0W5x4EHLBojpLvMOlQxQqZYYIMK713P+sJnqX2ciaSVayTAaG70
# 3TFDSrPLCW2+0yzoOAeVcmtP9n53vNZm/GcuOsUbV6or5a6oi7h5iwn1qBnUl12W
# Phd8fOLC+hA3sKqGJhhk/pK9lzSOaAcw5gfVaJ1FS5sRZNMuyqar9OixOdHC6blb
# hDKHWxvEg3Bect4ozk8IZSZNXggLAZ0UGE8Eep2KxWryGMpWT4C49iecFa0E6PAK
# epEyeJLjC6+a7ql4uUFOP2tATnO/d1TXvsdj/ZYuBawrzcJFpQ33JN9HCeim6F8Q
# 48ISv92W83UfwW5rCMZXOy2OC0lj0vrYVMbAhQmbeOIk4++NWE/TJhNE6M1+xT15
# c7gRtEr/auK77hls+xzrgdL5OJPdyTaTlPGZiTzXg/9ep+A0QORt8RbKH7t1eJTY
# TPD1i6mBlcJE41yYZ7vnsqsT9iBVYjghXluwKsgeZhU0n0V5DVwQvETu3KBbABAU
# X8i1oqYv6n40E80SZq73qJAz20sw
# SIG # End signature block
