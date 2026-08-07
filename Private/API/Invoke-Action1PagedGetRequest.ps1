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

# SIG # Begin signature block
# MII9MQYJKoZIhvcNAQcCoII9IjCCPR4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBVbieMlRBsW/tW
# HFloUY/72qQOl1baR04GhxEJefTMMqCCIfYwggXMMIIDtKADAgECAhBUmNLR1FsZ
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
# 03u4aUoqlmZpxJTG9F9urJh4iIAGXKKy7aIwggaoMIIEkKADAgECAhMzAAP2I1ek
# GJt95/XrAAAAA/YjMA0GCSqGSIb3DQEBDAUAMFoxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDUyBFT0MgQ0EgMDMwHhcNMjYwODA1MTkwNDI0WhcNMjYwODA4
# MTkwNDI0WjBrMQswCQYDVQQGEwJVUzEOMAwGA1UECBMFVGV4YXMxEDAOBgNVBAcT
# B0hvdXN0b24xHDAaBgNVBAoTE0FjdGlvbjEgQ29ycG9yYXRpb24xHDAaBgNVBAMT
# E0FjdGlvbjEgQ29ycG9yYXRpb24wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQCIHWR+7TAVyCmYrwtITk5YseeIaSaTKD4XkZFYUsydiKh6iEN/fzVWo6ZP
# JBdRUQvdOkchsjYw/orh7YVpGIaUMpzVZEHKleKkxNN6qeburauO4uTT357hKp2M
# kWxy4g74y7y8lDGOS0s/X1IFC+V2QbwSoLJyEEFtUjg2BSc7t9SUCBQoZcmCvQkL
# ZAuP6ZBomUOiFYHzg9YmkXLVmCgP2uMvniQnlYk9HpAL+E4bu75lDs58cin7XLkl
# eLT6ck4WTKj59AuEOZrxYhvITFsJZQh5E8X0OhS5Q2J/R8ucSX7gcR7f754rA9HK
# /+RqkW0oNVwXsAFN9G+G32j3p1yigxp2z+th/aVw6ZHeqC/gKJ0xM62iYMKEL7/m
# IFksXbwgwUgf6HYo3VOhCJaigClunSXx4hL7+6tCb1dXQ4k0Lgw5pwnEWmVLosRn
# c5rCxBgvmptbdi+RKJax1VLruJqktlgHKqQq1UmFE46TPCk+aqINHUy8EsU0ifwW
# zNc/s00CAwEAAaOCAdQwggHQMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeA
# MDsGA1UdJQQ0MDIGCisGAQQBgjdhAQAGCCsGAQUFBwMDBhorBgEEAYI3YYTGyjWC
# 84fIeoPTzfIboMPaLTAdBgNVHQ4EFgQU27hQuP0V5vnLZWhDUmyOKOz541AwHwYD
# VR0jBBgwFoAUa16lNMMFxWJKIVqOq3NgYtSsY4UwZwYDVR0fBGAwXjBcoFqgWIZW
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# SUQlMjBWZXJpZmllZCUyMENTJTIwRU9DJTIwQ0ElMjAwMy5jcmwwdAYIKwYBBQUH
# AQEEaDBmMGQGCCsGAQUFBzAChlhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUyMEVPQyUy
# MENBJTIwMDMuY3J0MFQGA1UdIARNMEswSQYEVR0gADBBMD8GCCsGAQUFBwIBFjNo
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5o
# dG0wDQYJKoZIhvcNAQEMBQADggIBAIk/uuylZyEv2HSh0xbQGOMLl5acO0OVJc0D
# ceaWsjHe+Rh10oDWB5umnoB0Y/hJjqZLhbf92fOcCBz4alvZPYHKq/ungDFWuIWA
# 9Xa5PSGNKORu0rzsAofewQbOpbJfVQyRZ3c3fbWneWmfvwIL/JUalkPblwnZpDkh
# ddbEdt5RkynlSRhXQkzM7rm3HaJuA/h0AliSroO7nF1Z+qQF/L+hIGD1FUW6gstb
# KEhkHV2IPwPedLwBvLVWpuVCX7m29VoX7n1FWOGrDjmwYzClLG/uOgPyx6cDVMLZ
# sKcn5HSjnG1jfC2P3fk7C9ANC8xNa6sQZeIZuVl6cNabR4H9R2McXXZsVuuk2TtI
# EiKOAVQU3zYZ+jkqylnpfeIrs8lyMTteUOsWSSRsOSwmZZqmoR8XZGLdIXSmdD6q
# o6aWGvq7/TECnnk3UCSaIPG8yiUayrfffdTGcbsmqEe4SW2wbeIpmy1O2kCJjo73
# nbS8yV6lk6RZb26uddvQCnAa/LD3JbfXSkaAjZY89joONCQ7Y5pIymbAmZ2XoRyT
# eBXDlRNJ0uZyVP1uFxlP5j3uwVLBZvJe657kZIbIAHoDxh1wmYg42DhCFpMmhbPz
# ZsS0m66cfXcjDpCMJR5M190+4wa+gG2PG+aNGuq/M5wXE9io59tT0tnnBueliAqQ
# 0F1DuG7TMIIGqDCCBJCgAwIBAgITMwAD9iNXpBibfef16wAAAAP2IzANBgkqhkiG
# 9w0BAQwFADBaMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgSUQgVmVyaWZpZWQgQ1MgRU9DIENB
# IDAzMB4XDTI2MDgwNTE5MDQyNFoXDTI2MDgwODE5MDQyNFowazELMAkGA1UEBhMC
# VVMxDjAMBgNVBAgTBVRleGFzMRAwDgYDVQQHEwdIb3VzdG9uMRwwGgYDVQQKExNB
# Y3Rpb24xIENvcnBvcmF0aW9uMRwwGgYDVQQDExNBY3Rpb24xIENvcnBvcmF0aW9u
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAiB1kfu0wFcgpmK8LSE5O
# WLHniGkmkyg+F5GRWFLMnYioeohDf381VqOmTyQXUVEL3TpHIbI2MP6K4e2FaRiG
# lDKc1WRBypXipMTTeqnm7q2rjuLk09+e4SqdjJFscuIO+Mu8vJQxjktLP19SBQvl
# dkG8EqCychBBbVI4NgUnO7fUlAgUKGXJgr0JC2QLj+mQaJlDohWB84PWJpFy1Zgo
# D9rjL54kJ5WJPR6QC/hOG7u+ZQ7OfHIp+1y5JXi0+nJOFkyo+fQLhDma8WIbyExb
# CWUIeRPF9DoUuUNif0fLnEl+4HEe3++eKwPRyv/kapFtKDVcF7ABTfRvht9o96dc
# ooMads/rYf2lcOmR3qgv4CidMTOtomDChC+/5iBZLF28IMFIH+h2KN1ToQiWooAp
# bp0l8eIS+/urQm9XV0OJNC4MOacJxFplS6LEZ3OawsQYL5qbW3YvkSiWsdVS67ia
# pLZYByqkKtVJhROOkzwpPmqiDR1MvBLFNIn8FszXP7NNAgMBAAGjggHUMIIB0DAM
# BgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDA7BgNVHSUENDAyBgorBgEEAYI3
# YQEABggrBgEFBQcDAwYaKwYBBAGCN2GExso1gvOHyHqD083yG6DD2i0wHQYDVR0O
# BBYEFNu4ULj9Feb5y2VoQ1Jsjijs+eNQMB8GA1UdIwQYMBaAFGtepTTDBcViSiFa
# jqtzYGLUrGOFMGcGA1UdHwRgMF4wXKBaoFiGVmh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUy
# MEVPQyUyMENBJTIwMDMuY3JsMHQGCCsGAQUFBwEBBGgwZjBkBggrBgEFBQcwAoZY
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQl
# MjBJRCUyMFZlcmlmaWVkJTIwQ1MlMjBFT0MlMjBDQSUyMDAzLmNydDBUBgNVHSAE
# TTBLMEkGBFUdIAAwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMA0GCSqGSIb3DQEBDAUAA4IC
# AQCJP7rspWchL9h0odMW0BjjC5eWnDtDlSXNA3HmlrIx3vkYddKA1gebpp6AdGP4
# SY6mS4W3/dnznAgc+Gpb2T2Byqv7p4AxVriFgPV2uT0hjSjkbtK87AKH3sEGzqWy
# X1UMkWd3N321p3lpn78CC/yVGpZD25cJ2aQ5IXXWxHbeUZMp5UkYV0JMzO65tx2i
# bgP4dAJYkq6Du5xdWfqkBfy/oSBg9RVFuoLLWyhIZB1diD8D3nS8Aby1VqblQl+5
# tvVaF+59RVjhqw45sGMwpSxv7joD8senA1TC2bCnJ+R0o5xtY3wtj935OwvQDQvM
# TWurEGXiGblZenDWm0eB/UdjHF12bFbrpNk7SBIijgFUFN82Gfo5KspZ6X3iK7PJ
# cjE7XlDrFkkkbDksJmWapqEfF2Ri3SF0pnQ+qqOmlhr6u/0xAp55N1AkmiDxvMol
# Gsq3333UxnG7JqhHuEltsG3iKZstTtpAiY6O9520vMlepZOkWW9urnXb0ApwGvyw
# 9yW310pGgI2WPPY6DjQkO2OaSMpmwJmdl6Eck3gVw5UTSdLmclT9bhcZT+Y97sFS
# wWbyXuue5GSGyAB6A8YdcJmIONg4QhaTJoWz82bEtJuunH13Iw6QjCUeTNfdPuMG
# voBtjxvmjRrqvzOcFxPYqOfbU9LZ5wbnpYgKkNBdQ7hu0zCCBygwggUQoAMCAQIC
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
# BgNVBAMTIk1pY3Jvc29mdCBJRCBWZXJpZmllZCBDUyBFT0MgQ0EgMDMCEzMAA/Yj
# V6QYm33n9esAAAAD9iMwDQYJYIZIAWUDBAIBBQCgXjAQBgorBgEEAYI3AgEMMQIw
# ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAvBgkqhkiG9w0BCQQxIgQgt3NH
# 5soB6JD9Tops+tWbda8/7ghsdeN9klUMi13/wycwDQYJKoZIhvcNAQEBBQAEggGA
# gyog9xYh94sCPFl0U8EZao5xYnxl5jnBsmok6kz9yywpSDotyU5n7mE90XTEDUuW
# WoO6h5961XCMxe0Nd4pf+xUqQFJvO9IXGxD06QUr9gvws0fUvA7HygoUccVCL9Xw
# 1v0r1ROnSbOR+y3Wx+mnc8COU4qus4MDTs+Wfa1LQbzxyeUcjhrpZ9HDoigK8diz
# 4Fl86fh7sySlUT1OS4/waTuLpkFi8LfQMJTTiWNDn04Dve4DqLPpTcH9Jw+AxAeh
# TXdXk9ofJOl72HdhjHuUA9DNuMZuvFmTBuwBc1363Had2/fwiMbQ+/wSs5HHLCsU
# veczhDPpqpK8H4ym0l5tBG8h69lmKanQe7YybqxVihdz5j2B9M1Q2lOo2I4rWvGT
# BY6myjkS/UnmcN48ecMskLZsY6bAYjfmRKvU/IDWI64vEBCub+XjbUc55d09ftCw
# lmfgMNghU+XCwt1DtD59FF2bgdGXihunCR0umBXFH+ze4T29TownSqGKw6egdgL9
# oYIYETCCGA0GCisGAQQBgjcDAwExghf9MIIX+QYJKoZIhvcNAQcCoIIX6jCCF+YC
# AQMxDzANBglghkgBZQMEAgEFADCCAWIGCyqGSIb3DQEJEAEEoIIBUQSCAU0wggFJ
# AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIGBSIsNgTE580mq0UEm/
# 99XMkmUOGkA/yqc4hwEeJrvnAgZqaJ502d4YEzIwMjYwODA3MDkwNTQzLjQ5Nlow
# BIACAfSggeGkgd4wgdsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNV
# BAsTHm5TaGllbGQgVFNTIEVTTjpBNTAwLTA1RTAtRDk0NzE1MDMGA1UEAxMsTWlj
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
# AF1bMIIHlzCCBX+gAwIBAgITMwAAAFZ+j51YCI7pYAAAAAAAVjANBgkqhkiG9w0B
# AQwFADBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcg
# Q0EgMjAyMDAeFw0yNTEwMjMyMDQ2NTFaFw0yNjEwMjIyMDQ2NTFaMIHbMQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3Nv
# ZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046
# QTUwMC0wNUUwLUQ5NDcxNTAzBgNVBAMTLE1pY3Jvc29mdCBQdWJsaWMgUlNBIFRp
# bWUgU3RhbXBpbmcgQXV0aG9yaXR5MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAtKWfm/ul027/d8Rlb8Mn/g0QUvvLqY2Vsy3tI8U2tFSspTZomZOD3BHT
# 8LkR+RrhMJgb1VjAKFNysaK9cLSXifPGSIBrPCgs9P4y24lrJEmrV6Q5z4BmqMhI
# PrZhEvZnWpCS4HO7jYSei/nxmC7/1Er+l5Lg3PmSxb8d2IVcARxSw1B4mxB6XI0n
# kel9wa1dYb2wfGpofraFmxZOxT9eNht4LH0RBSVueba6ZNpjS/0gtfm7qiIiyP6p
# 6PRzTTbMnVqsHnV/d/rW0zHx+Q+QNZ5wUqKmTZJB9hU853+2pX5rDfK32uNY9/WB
# OAmzbqgpEdQkbiMavUMyUDShmycIvgHdQnS207sTj8M+kJL3tOdahPuPqMwsaCCg
# dfwwQx0O9TKe7FSvbAEYs1AnldCl/KHGZCOVvUNqjyL10JLe0/+GD9/ynqXGWFpX
# OjaunvZ/cKROhjN4M5e6xx0b2miqcPii4/ii2ZheKallJET7CKlpFShs3wyg6F/f
# ojQxQvPnbWD4Nyx6lhjWjwmoLcx6w1FSCtavLCly33BLRSlTU4qKUxaa8d7YN7Eq
# pn9XO0SY0umOvKFXrWH7rxl+9iaicitdnTTksAnRjvekdKT3lg7lRMfmfZU8vXNi
# N0UYJzT9EjqjRm0uN/h0oXxPhNfPYqeFbyPXGGxzaYUz6zx3qTcCAwEAAaOCAcsw
# ggHHMB0GA1UdDgQWBBS+tjPyu6tZ/h5GsyLvyz1H+FNIWjAfBgNVHSMEGDAWgBRr
# aSg6NS9IY0DPe9ivSek+2T3bITBsBgNVHR8EZTBjMGGgX6BdhltodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBQdWJsaWMlMjBS
# U0ElMjBUaW1lc3RhbXBpbmclMjBDQSUyMDIwMjAuY3JsMHkGCCsGAQUFBwEBBG0w
# azBpBggrBgEFBQcwAoZdaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# ZXJ0cy9NaWNyb3NvZnQlMjBQdWJsaWMlMjBSU0ElMjBUaW1lc3RhbXBpbmclMjBD
# QSUyMDIwMjAuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUH
# AwgwDgYDVR0PAQH/BAQDAgeAMGYGA1UdIARfMF0wUQYMKwYBBAGCN0yDfQEBMEEw
# PwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9j
# cy9SZXBvc2l0b3J5Lmh0bTAIBgZngQwBBAIwDQYJKoZIhvcNAQEMBQADggIBAA4D
# qAXEsO26j/La7Fgn/Qifit8xuZekqZ57+Ye+sH/hRTbEEjGYrZgsqwR/lUUfKCFp
# bZF8msaZPQJOR4YYUEU8XyjLrn8Y1jCSmoxh9l7tWiSoc/JFBw356JAmzGGxeBA2
# EWSxRuTr1AuZe6nYaN8/wtFkiHcs8gMadxXBs6DxVhyu5YnhLPQkfumKm3lFftwE
# 7pieV7f1lskmlgsC6AeSGCzGPZUgCvcH5Tv/Qe9z7bIImSD3SuzhOIwaP+eKQTYf
# 67TifyJKkWQSdGfTA6Kcu41k8LB6oPK+MLk1jbxxK5wPqLSL62xjK04SBXHEJSEn
# sFt0zxWkxP/lgej1DxqUnmrYEdkxvzKSHIAqFWSZul/5hI+vJxvFPhsNQBEk4cSu
# lDkJQpcdVi/gmf/mHFOYhDBjsa15s4L+2sBil3XV/T8RiR66Q8xYvTLRWxd2dVsr
# OoCwnsU4WIeiC0JinCv1WLHEh7Qyzr9RSr4kKJLWdpNYLhgjkojTmEkAjFO774t3
# xB7enbvIF0GOsV19xnCUzq9EGKyt0gMuaphKlNjJ+aTpjWMZDGo+GOKsnp93Hmft
# ml0Syp3F9+M3y+y6WJGUZoIZJq227jDjjEndtpUrh9BdPdVIfVJD/Au81Rzh05UH
# AivorQ3Os8PELHIgiOd9TWzbdgmGzcILt/ddVQERMYIHQzCCBz8CAQEweDBhMQsw
# CQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYD
# VQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMAIT
# MwAAAFZ+j51YCI7pYAAAAAAAVjANBglghkgBZQMEAgEFAKCCBJwwEQYLKoZIhvcN
# AQkQAg8xAgUAMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0B
# CQUxDxcNMjYwODA3MDkwNTQzWjAvBgkqhkiG9w0BCQQxIgQgQ9vcvh/Nx/rHlKTY
# gaY07q1BGckU031xkvveDPt6nx4wgbkGCyqGSIb3DQEJEAIvMYGpMIGmMIGjMIGg
# BCC2DDMlTaTj8JV3iTg5Xnpe4CSH60143Z+X9o5NBgMMqDB8MGWkYzBhMQswCQYD
# VQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQD
# EylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMAITMwAA
# AFZ+j51YCI7pYAAAAAAAVjCCA14GCyqGSIb3DQEJEAISMYIDTTCCA0mhggNFMIID
# QTCCAikCAQEwggEJoYHhpIHeMIHbMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046QTUwMC0wNUUwLUQ5NDcxNTAzBgNV
# BAMTLE1pY3Jvc29mdCBQdWJsaWMgUlNBIFRpbWUgU3RhbXBpbmcgQXV0aG9yaXR5
# oiMKAQEwBwYFKw4DAhoDFQD/c/cpFSqQWYBeXggyRJ2ZbvYEEaBnMGWkYzBhMQsw
# CQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYD
# VQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMDAN
# BgkqhkiG9w0BAQsFAAIFAO4foyYwIhgPMjAyNjA4MDcwMDE5NTBaGA8yMDI2MDgw
# ODAwMTk1MFowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA7h+jJgIBADAHAgEAAgIy
# +zAHAgEAAgISSDAKAgUA7iD0pgIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEE
# AYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBCwUAA4IB
# AQA3DUWkEFXiRGmHmN4yTaaI1U3o1BO21f1Enk2ZXSUfe/Psz+YQFKnJvZ00Vovt
# 1f8FsU1CStbi475V6zZcCfZphG59lsrvs4xMsDvyxWXQB+YWbmqJCOaUn/BLr7Hz
# 1F4f69QSYbaPeH5XLgZKeEzkuV5Rm0znMwF2BnG1qGOHKe40PiYGUyJ7jbrXyx7/
# 8HcM+IWuEJzJKQVVypzjWEpb2m58u6RkpG7QW/n13xIOuj3Me5JtiRmURIJKv49a
# kdM/SrLyxBrRoubo6Gg4Vck9EoKNgZmZNGr6Od8ISsKieiWnI/VocP2wQp15YGbf
# 0AXkbGGpGfYpTAFqYTaAUS+GMA0GCSqGSIb3DQEBAQUABIICAJd5yK+5JJHDYGx1
# iqDSMqt8dj0FfAAnODxUSbxtFn0Fk6rJADDToHP9MFcZdy2V/pOP98rsCwUKbgqx
# 5HLnPcvFD1mHRt6mu3EzRW9F+gX/Myc7Z7qDgN6GWpT6xe9SkIYeRNNm3dCWBOkO
# YhIf+qjh1NqILSh+eS7Cz0Fvi3Pq4ufKLS/uQfSSJJ3m0rUKnmmpRfRNCC3Zna3p
# J4ZyD9srLY310AXw+OTHBaJ6XcH6dwFfZo1RAa9W6fwJ6pZ0ZVA9tplOo+w5WzxT
# KdXlLLM2lndWSnXP+dwo6uP7Z3pYP2MxRUxJyvZakFDYkyPSCuGSdkVRuEHB6qPp
# UwgnJ1b/efJoy2BADg0WrWOmdFLZaaBQU/UGjLAJUZlKAFl4b0NKTtChfmC+DlL9
# k6lDUa5vAjMhcgurWboESr1OpeDkKD+jMv+SgJJj01jOzi/aN9V1HRTxSd3CjSwk
# VKCLq2DcDvp1aQvCllbNhrw69YIr9qWC0SPNycoihIR+1+IoXMsohNVNx922WqYB
# DUV/7fMqLddfwPpI+NQlm1njGzatPJY3HvAhM0ZXKKb4TnaFAXkgagpwV6Ln/w1l
# CSYfRARRPUXqa0ImeqXojHULrQpVYpDG7fhTirBDdxuLJc00MA7Oi3vnI5IMmi+O
# ZSEExSWWU0Puw4bCFAQ1EUDKDSVx
# SIG # End signature block
