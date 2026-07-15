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
# 03u4aUoqlmZpxJTG9F9urJh4iIAGXKKy7aIwggaoMIIEkKADAgECAhMzAAMg1FN7
# z5V+A7MkAAAAAyDUMA0GCSqGSIb3DQEBDAUAMFoxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDUyBBT0MgQ0EgMDQwHhcNMjYwNzEzMTUzOTA0WhcNMjYwNzE2
# MTUzOTA0WjBrMQswCQYDVQQGEwJVUzEOMAwGA1UECBMFVGV4YXMxEDAOBgNVBAcT
# B0hvdXN0b24xHDAaBgNVBAoTE0FjdGlvbjEgQ29ycG9yYXRpb24xHDAaBgNVBAMT
# E0FjdGlvbjEgQ29ycG9yYXRpb24wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQCNwDAs5op7APk5uUPYAgbRb2tJNxYsx8JY4aZXu/0qaJJkt3lUJQaCozB7
# ap0g75oMnpmFDCqWbJ9qr0iAddS4niPr6dACq7MtV5VcLDUd/kyl6MEK/jmKODYs
# 7gSoIoq64WZ5gfIjoDCBJP0OpQu2KDP4G5ActlSq/vvAGocmrW8Q8sNPvdEQVLWn
# N3EG7sYZLDpNgdysnufYuMrBVCkmYVLG3T0/JWDIpxyRCVyEv/bH2x++cPb5LC2O
# Ksek8AeW1YXumt2o/ULc2JcIQ6WG/eWgb1vFqSTFT/GntmNUFiKckHI6fiG5ZC4a
# n014W5fCxi8f/xLH5QqVQN5ewk3rVUkf924MIDyBrcH/Zng3dafzM7AGTfBKJjK1
# qGlOZtP6y2BU7CnbTNOmJVCvVM/v4AbMWgh2dcEk6/hlFAN5Tdk/x4wlRsQWRnY/
# 8QPohB2EIRhri3b9g6E1eeY5EkoKORo4OgRWqp6FrTtwh19B3CcDJhg3pnGhTxOI
# PO+CnQMCAwEAAaOCAdQwggHQMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeA
# MDsGA1UdJQQ0MDIGCisGAQQBgjdhAQAGCCsGAQUFBwMDBhorBgEEAYI3YYTGyjWC
# 84fIeoPTzfIboMPaLTAdBgNVHQ4EFgQU4vhJ3Va1KwhpAtZ1EwPqRKGO4j0wHwYD
# VR0jBBgwFoAUayVB3vtrfP0YgAotf492XapzPbgwZwYDVR0fBGAwXjBcoFqgWIZW
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# SUQlMjBWZXJpZmllZCUyMENTJTIwQU9DJTIwQ0ElMjAwNC5jcmwwdAYIKwYBBQUH
# AQEEaDBmMGQGCCsGAQUFBzAChlhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUyMEFPQyUy
# MENBJTIwMDQuY3J0MFQGA1UdIARNMEswSQYEVR0gADBBMD8GCCsGAQUFBwIBFjNo
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5o
# dG0wDQYJKoZIhvcNAQEMBQADggIBALaZZMk3OyXrNvHsvv48nfr5zh4J6JnFjeUz
# exIz/FeozYnx7jei51lRo9ImEN8rdmdro4CZhBNKfldByTfXI7bpNXiD2CxWNh5A
# LzQYZsiNAiXsZ+hTSb/7bL7ya3zefMWg2Axe+cUboYUgK5V39VcjGQL3eMQC2UhG
# lWpRvVGe3CM5O1vImYZgJSuydxaVKRcIgfU6pcxhQxClsqGmWT9DHVomUWinD1Sf
# vTNr4FrXtQPtK+uj2uMp1Shlg1X64MnTugLextlfuj+KNg9mQexuzbRirFJzgmAb
# 18tV6Yd85H+/nEDBreRlr3VHsSLKlPgUxyWr5pTVC5jc5Pp/22BXUqd0RV9BmR18
# iqKc5g6bGon6+WCAeqMpH6cX5I6UX47VEU28LL34PlYx+IEB6bqs3lAQRDmF1Rdc
# U3u7zTFGKD6wpKNFY7ygw7snAzNvHlb/Q7M9oVE0/Cvh0VXeMM8AwYfEhnBTTmS9
# kN/FZBmjlOews5BY2Qhm4nMzrrNnLrkvbJUoBDSRBJOpLamVCnSILp0YtzwbTH+V
# 892d9OdgnQ3tDmW0QLRz05nkgbhnQC5FjGQK7KIc8A3ZQsDPdE0trsycaS1i4CDC
# RUi7UIsIVjJW7JPtimo78OE2B7xztH4fI1KtIwBS+fZy4KqmkT4PJMrMJZtM//1D
# g5dnVynnMIIGqDCCBJCgAwIBAgITMwADINRTe8+VfgOzJAAAAAMg1DANBgkqhkiG
# 9w0BAQwFADBaMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgSUQgVmVyaWZpZWQgQ1MgQU9DIENB
# IDA0MB4XDTI2MDcxMzE1MzkwNFoXDTI2MDcxNjE1MzkwNFowazELMAkGA1UEBhMC
# VVMxDjAMBgNVBAgTBVRleGFzMRAwDgYDVQQHEwdIb3VzdG9uMRwwGgYDVQQKExNB
# Y3Rpb24xIENvcnBvcmF0aW9uMRwwGgYDVQQDExNBY3Rpb24xIENvcnBvcmF0aW9u
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAjcAwLOaKewD5OblD2AIG
# 0W9rSTcWLMfCWOGmV7v9KmiSZLd5VCUGgqMwe2qdIO+aDJ6ZhQwqlmyfaq9IgHXU
# uJ4j6+nQAquzLVeVXCw1Hf5MpejBCv45ijg2LO4EqCKKuuFmeYHyI6AwgST9DqUL
# tigz+BuQHLZUqv77wBqHJq1vEPLDT73REFS1pzdxBu7GGSw6TYHcrJ7n2LjKwVQp
# JmFSxt09PyVgyKcckQlchL/2x9sfvnD2+SwtjirHpPAHltWF7prdqP1C3NiXCEOl
# hv3loG9bxakkxU/xp7ZjVBYinJByOn4huWQuGp9NeFuXwsYvH/8Sx+UKlUDeXsJN
# 61VJH/duDCA8ga3B/2Z4N3Wn8zOwBk3wSiYytahpTmbT+stgVOwp20zTpiVQr1TP
# 7+AGzFoIdnXBJOv4ZRQDeU3ZP8eMJUbEFkZ2P/ED6IQdhCEYa4t2/YOhNXnmORJK
# CjkaODoEVqqeha07cIdfQdwnAyYYN6ZxoU8TiDzvgp0DAgMBAAGjggHUMIIB0DAM
# BgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDA7BgNVHSUENDAyBgorBgEEAYI3
# YQEABggrBgEFBQcDAwYaKwYBBAGCN2GExso1gvOHyHqD083yG6DD2i0wHQYDVR0O
# BBYEFOL4Sd1WtSsIaQLWdRMD6kShjuI9MB8GA1UdIwQYMBaAFGslQd77a3z9GIAK
# LX+Pdl2qcz24MGcGA1UdHwRgMF4wXKBaoFiGVmh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUy
# MEFPQyUyMENBJTIwMDQuY3JsMHQGCCsGAQUFBwEBBGgwZjBkBggrBgEFBQcwAoZY
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQl
# MjBJRCUyMFZlcmlmaWVkJTIwQ1MlMjBBT0MlMjBDQSUyMDA0LmNydDBUBgNVHSAE
# TTBLMEkGBFUdIAAwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMA0GCSqGSIb3DQEBDAUAA4IC
# AQC2mWTJNzsl6zbx7L7+PJ36+c4eCeiZxY3lM3sSM/xXqM2J8e43oudZUaPSJhDf
# K3Zna6OAmYQTSn5XQck31yO26TV4g9gsVjYeQC80GGbIjQIl7GfoU0m/+2y+8mt8
# 3nzFoNgMXvnFG6GFICuVd/VXIxkC93jEAtlIRpVqUb1RntwjOTtbyJmGYCUrsncW
# lSkXCIH1OqXMYUMQpbKhplk/Qx1aJlFopw9Un70za+Ba17UD7Svro9rjKdUoZYNV
# +uDJ07oC3sbZX7o/ijYPZkHsbs20YqxSc4JgG9fLVemHfOR/v5xAwa3kZa91R7Ei
# ypT4FMclq+aU1QuY3OT6f9tgV1KndEVfQZkdfIqinOYOmxqJ+vlggHqjKR+nF+SO
# lF+O1RFNvCy9+D5WMfiBAem6rN5QEEQ5hdUXXFN7u80xRig+sKSjRWO8oMO7JwMz
# bx5W/0OzPaFRNPwr4dFV3jDPAMGHxIZwU05kvZDfxWQZo5TnsLOQWNkIZuJzM66z
# Zy65L2yVKAQ0kQSTqS2plQp0iC6dGLc8G0x/lfPdnfTnYJ0N7Q5ltEC0c9OZ5IG4
# Z0AuRYxkCuyiHPAN2ULAz3RNLa7MnGktYuAgwkVIu1CLCFYyVuyT7YpqO/DhNge8
# c7R+HyNSrSMAUvn2cuCqppE+DyTKzCWbTP/9Q4OXZ1cp5zCCBygwggUQoAMCAQIC
# EzMAAAAWMZKNkgJle5oAAAAAABYwDQYJKoZIhvcNAQEMBQAwYzELMAkGA1UEBhMC
# VVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE0MDIGA1UEAxMrTWlj
# cm9zb2Z0IElEIFZlcmlmaWVkIENvZGUgU2lnbmluZyBQQ0EgMjAyMTAeFw0yNjAz
# MjYxODExMjlaFw0zMTAzMjYxODExMjlaMFoxCzAJBgNVBAYTAlVTMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJRCBW
# ZXJpZmllZCBDUyBBT0MgQ0EgMDQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQDKVfrI2+gJMM/0bQ5OVKNdvOASzLbUUMvXuf+Vl7YGuofPaZHVo3gMHF5i
# nT+GMSpIcfIZ9qtXU1UG68ry8vNbQtOL4Nm30ifXpqI1+ByiAWLO1YT0WnzG7XPO
# uoTeeWsNZv5FmjxCsReBZvyzyzCyXZbu1EQfJxWTH4ebUwtAiW9rqMf9eDj/wYhi
# EfNteJV3ZFeibD2ztCHr9JhFdd97XbnCHgQoTIqc02X5xlRKtUGBa++OtHBBjiJ/
# uwBnzTkqu4FjpZjQeJtrmda+ur1CT2jflWIB/ypn7u7V9tvW9wJbJYt/H2EtJ0GO
# NWxJZ7TEu8jWPindOO3lzPP7UtzS/mVDV94HucWaltmsra6zSG8BoEJ87IM8QSb7
# vfm/O41FhYkUv89WIj5ES2O4kxyiMSfe95CMivCuYrRP2hKvx7egPMrWgDDBkxML
# grKZO9hRNUMm8vk3w5b9SogHOyJVhxyFm8aFXfIxgqDF4S0g4bhbhnzljmSlCLlu
# mMZcXFGDjpF2tNoAu3VGFGYtHtTSNVKvZpgB3b4ynaoDkbPf+Wg4523jt4VneasB
# gZhC1srZI2NCnCBBfgjLq04pqEKAWEohyW2K29KSkkHvt5VaE1ac3Yt+oyiOzMS5
# 7tXwQDJLGvLg/OXFO0VNvczDndfIfXYExB/ab2PuMSwd5VIBOwIDAQABo4IB3DCC
# AdgwDgYDVR0PAQH/BAQDAgGGMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRr
# JUHe+2t8/RiACi1/j3ZdqnM9uDBUBgNVHSAETTBLMEkGBFUdIAAwQTA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9z
# aXRvcnkuaHRtMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMBIGA1UdEwEB/wQI
# MAYBAf8CAQAwHwYDVR0jBBgwFoAU2UEpsA8PY2zvadf1zSmepEhqMOYwcAYDVR0f
# BGkwZzBloGOgYYZfaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwv
# TWljcm9zb2Z0JTIwSUQlMjBWZXJpZmllZCUyMENvZGUlMjBTaWduaW5nJTIwUENB
# JTIwMjAyMS5jcmwwfQYIKwYBBQUHAQEEcTBvMG0GCCsGAQUFBzAChmFodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIw
# VmVyaWZpZWQlMjBDb2RlJTIwU2lnbmluZyUyMFBDQSUyMDIwMjEuY3J0MA0GCSqG
# SIb3DQEBDAUAA4ICAQAG1VBeVHTVRBljlcZD3IiMxwPyMjQyLNaEnVu5mODm2hRB
# JfH8GsBLATmrHAc8F47jmk5CnpUPiIguCbw6Z/KVj4Dsoiq228NSLMLewFfGMri7
# uwNGLISC5ccp8vUdADDEIsS2dE+QI9OwkDpv3XuUD7d+hAgcLVcMOl1AsfEZtsZe
# nhGvSYUrm/FuLq0BqEGL9GXM5c+Ho9q8o+Vn/S+GWQN2y+gkRO15s0kI05nUpq/d
# OD4ri9rgVs6tipEd0YZqGgD+CZNiaZWrDTOQbNPncd2F9qOsUa20miYruoT5PwJA
# aI+QQiTE2ZJeMJOkOpzhTUgqVMZwZidEUZKCqudaeQA08WwnkQMfKyHzaU8j48UL
# cU4hUwvMsv7fSurOe9GAdRQCPvF8WcSK5oDHe8VVJM4tv6KKCm91HqLx9JamBgRI
# 6R2SfY3nu26EGznu0rCg/769z8xWm4PVcC2ZaL6VlKVqFp1NsN8YqMyf5t+bbGVb
# 09noFKcJG/UwyGlxRmQBlfeBUQx5/ytlzZzsEnhrJF9fTAfje8j3OdX5lEnePTFQ
# LRlvzZFBqUXnIeQKv3fHQjC9m2fo/Z01DII/qp3d8LhGVUW0BCG04fRwHJNH8iqq
# CG/qofMv+kym2AxBDnHzNgRjL60JOFiBgiurvLhYQNhB95KWojFA6shQnggkMTCC
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
# BgNVBAMTIk1pY3Jvc29mdCBJRCBWZXJpZmllZCBDUyBBT0MgQ0EgMDQCEzMAAyDU
# U3vPlX4DsyQAAAADINQwDQYJYIZIAWUDBAIBBQCgXjAQBgorBgEEAYI3AgEMMQIw
# ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAvBgkqhkiG9w0BCQQxIgQgt3NH
# 5soB6JD9Tops+tWbda8/7ghsdeN9klUMi13/wycwDQYJKoZIhvcNAQEBBQAEggGA
# UY5jzO2+phRhwOZW0eiFV3BiNKQK8/yAQ7F3/QzAo2OVI76RWdOdRpb3d2ROwIje
# 45ewVYLp++gEmD+0DLkQQaz6hl/gqHDMASpKJm5zg+7PVs5GG18pP07ITpbgD6+c
# fNp6KFJQAlTITWxK+CzxqS5vj29/bTSj51I8vm9YzWYSZUkTWXPUj8zDRTHdLPQj
# 3ALk/j+Ov/eElnusIoN7JNZQ9qJvW1T5JdMi9J7JQCS1V0vZJEf/8jsg69yTZVZ5
# Q+akdZV98wB+5oR+2vSM3tCUBEgPHx+fm2T0DduKNO42hHKoev9mOl/KHKQ86pin
# gq+aHIHR50ryhUwA4EhlJgxvcc0KLqALaYGoxf8Zwc/mXjF5V/AhMjhIoBsMWaDs
# 0gRHbjS0vY6HUGNa7HwgXQSTDyEyNhEANt6CXFVcnyosfBMhQt7SkVb2kvT7mfCy
# 6LURVWI60zT3a7bichBtMP0CMAavZ4XFP4Tv23D6sPskiwJJvUUAwkC7tAYlBm6+
# oYIYETCCGA0GCisGAQQBgjcDAwExghf9MIIX+QYJKoZIhvcNAQcCoIIX6jCCF+YC
# AQMxDzANBglghkgBZQMEAgEFADCCAWIGCyqGSIb3DQEJEAEEoIIBUQSCAU0wggFJ
# AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIF/47RreDR5ce4q5Ff+V
# cRI2F9dzsQgpz7++jzfNN/h1AgZqVWCSVrUYEzIwMjYwNzE1MTI1NTU5LjQ1OFow
# BIACAfSggeGkgd4wgdsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNV
# BAsTHm5TaGllbGQgVFNTIEVTTjo3RDAwLTA1RTAtRDk0NzE1MDMGA1UEAxMsTWlj
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
# AF1bMIIHlzCCBX+gAwIBAgITMwAAAFXZ3WkmKPn44gAAAAAAVTANBgkqhkiG9w0B
# AQwFADBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcg
# Q0EgMjAyMDAeFw0yNTEwMjMyMDQ2NDlaFw0yNjEwMjIyMDQ2NDlaMIHbMQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3Nv
# ZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046
# N0QwMC0wNUUwLUQ5NDcxNTAzBgNVBAMTLE1pY3Jvc29mdCBQdWJsaWMgUlNBIFRp
# bWUgU3RhbXBpbmcgQXV0aG9yaXR5MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAvbkfkh5ZSLP0MCUWafaw/KZoVZu9iQx8r5JwhZvdrUi86UjCCFQONjQa
# nrIxGF9hRGIZLQZ50gHrLC+4fpUEJff5t04VwByWC2/bWOuk6NmaTh9JpPZDcGzN
# R95QlryjfEjtl+gxj12zNPEdADPplVfzt8cYRWFBx/Fbfch08k6P9p7jX2q1jFPb
# UxWYJ+xOyGC1aKhDGY5b+8wL39v6qC0HFIx/v3y+bep+aEXooK8VoeWK+szfaFjX
# o8YTcvQ8UL4szu9HFTuZNv6vvoJ7Ju+o5aTj51sph+0+FXW38TlL/rDBd5ia79js
# kLtOeHbDjkbljilwzegcxv9i49F05ZrS/5ELZCCY1VaqO7EOLKVaxxdAO5oy1vb0
# Bx0ZRVX1mxFjYzay2EC051k6yGJHm58y1oe2IKRa/SM1+BTGse6vHNi5Q2d5ZnoR
# 9AOAUDDwJIIqRI4rZz2MSinh11WrXTG9urF2uoyd5Ve+8hxes9ABeP2PYQKlXYTA
# xvdaeanDTQ/vwmnM+yTcWzrVm84Z38XVFw4G7p/ZNZ2nscvv6uru2AevXcyV1t8h
# a7iWmhhgTWBNBrViuDlc3iPvOz2SVPbPeqhyY/NXwNZCAgc2H5pOztu6MwQxDIjt
# e3XM/FkKBxHofS2abNT/0HG+xZtFqUJDaxgbJa6lN1zh7spjuQ8CAwEAAaOCAcsw
# ggHHMB0GA1UdDgQWBBRWBF8QbdwIA/DIv6nJFsrB16xltjAfBgNVHSMEGDAWgBRr
# aSg6NS9IY0DPe9ivSek+2T3bITBsBgNVHR8EZTBjMGGgX6BdhltodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBQdWJsaWMlMjBS
# U0ElMjBUaW1lc3RhbXBpbmclMjBDQSUyMDIwMjAuY3JsMHkGCCsGAQUFBwEBBG0w
# azBpBggrBgEFBQcwAoZdaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# ZXJ0cy9NaWNyb3NvZnQlMjBQdWJsaWMlMjBSU0ElMjBUaW1lc3RhbXBpbmclMjBD
# QSUyMDIwMjAuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUH
# AwgwDgYDVR0PAQH/BAQDAgeAMGYGA1UdIARfMF0wUQYMKwYBBAGCN0yDfQEBMEEw
# PwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9j
# cy9SZXBvc2l0b3J5Lmh0bTAIBgZngQwBBAIwDQYJKoZIhvcNAQEMBQADggIBAFIe
# 4ZJUe9qUKcWeWypchB58fXE/ZIWv2D5XP5/k/tB7LCN9BvmNSVKZ3VeclQM978wf
# EvuvdMQSUv6Y20boIM8DK1K1IU9cP21MG0ExiHxaqjrikf2qbfrXIip4Ef3v2bNY
# KQxCxN3Sczp1SX0H7uqK2L5OhfDEiXf15iou5hh+EPaaqp49czNQpJDOR/vfJghU
# c/qcslDPhoCZpZx8b2ODvywGQNXwqlbsmCS24uGmEkQ3UH5JUeN6c91yasVchS78
# riMrm6R9ZpAiO5pfNKMGU2MLm1A3pp098DcbFTAc95Hh6Qvkh//28F/Xe2bMFb6D
# L7Sw0ZO95v0gv0ZTyJfxS/LCxfraeEII9FSFOKAMEp1zNFSs2ue0GGjBt9yEEMUw
# vxq9ExFz0aZzYm8ivJfffpIVDnX/+rVRTYcxIkQyFYslIhYlWF9SjCw5r49qakjM
# RNh8W9O7aaoolSVZleQZjGt0K8JzMlyp6hp2lbW6XqRx2cOHbbxJDxmENzohGUzi
# I13lI2g2Bf5qibfC4bKNRpJo9lbE8HUbY0qJiE8u3SU8eDQaySPXOEhJjxRCQwwO
# vejYmBG5P7CckQNBSnnl12+FKRKgPoj0Mv+z5OMhj9z2MtpbnHLAkep0odQClEyy
# CG/uR5tK5rW6mZH5Oq56UWS0NI6NV1JGS7Jri6jFMYIHQzCCBz8CAQEweDBhMQsw
# CQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYD
# VQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMAIT
# MwAAAFXZ3WkmKPn44gAAAAAAVTANBglghkgBZQMEAgEFAKCCBJwwEQYLKoZIhvcN
# AQkQAg8xAgUAMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0B
# CQUxDxcNMjYwNzE1MTI1NTU5WjAvBgkqhkiG9w0BCQQxIgQglvA77NNTirY+8qgl
# MiwfwARk50OU+pEF/E1A/8r8kmswgbkGCyqGSIb3DQEJEAIvMYGpMIGmMIGjMIGg
# BCDYuTyXZIZiu799/v4PaqsmeSzBxh0rqkYq7sYYavj+zTB8MGWkYzBhMQswCQYD
# VQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQD
# EylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMAITMwAA
# AFXZ3WkmKPn44gAAAAAAVTCCA14GCyqGSIb3DQEJEAISMYIDTTCCA0mhggNFMIID
# QTCCAikCAQEwggEJoYHhpIHeMIHbMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046N0QwMC0wNUUwLUQ5NDcxNTAzBgNV
# BAMTLE1pY3Jvc29mdCBQdWJsaWMgUlNBIFRpbWUgU3RhbXBpbmcgQXV0aG9yaXR5
# oiMKAQEwBwYFKw4DAhoDFQAdO1QBgmW/tuBZV5EGjhfsV4cN6qBnMGWkYzBhMQsw
# CQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYD
# VQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMDAN
# BgkqhkiG9w0BAQsFAAIFAO4B2VQwIhgPMjAyNjA3MTUxMDAzMDBaGA8yMDI2MDcx
# NjEwMDMwMFowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA7gHZVAIBADAHAgEAAgIQ
# UTAHAgEAAgISbjAKAgUA7gMq1AIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEE
# AYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBCwUAA4IB
# AQByUjcmKLlhYn4ubnhvSbbPgxjQUxOrQNgZfy/DVDNGAsOiOVaUDN3j5E2TKzik
# xjaWZiFV9tsI9gtWLEeM9jXvX8li/WYcb6Vt/Z4WEpDELXCB86QTXvJNQb4M6YjW
# EtH7JEaCy7alZ7h2EDUCAOholNF/yt8/iAlysqDj3a9/zTEC4cBAPg9Epu2n3WBR
# Vqsi++lTH6I1ahZHg/KCbKEwAYmcLFPtDSH3wlHj93GJ190EbW8oKR5CG7GYAkwy
# Goia8G8l7W05tSgMgWFAp3AV+kjFIyJ/ChGZClAy7T3Ks6KYd9+w4hbCZJix08wa
# 6QH5NCi3bozEnwAvYG0a4LAAMA0GCSqGSIb3DQEBAQUABIICADrfshApdp9lpy60
# OD8hs1S0BeaW85F6RrSukfJOKuh1SQkABdmxtGiqWkRWVYqP5ZtB/0l5e33ZLH0t
# CpbYp0CRDQg7JsuG/87QYknA6l8GkWOtDgVSvu7+FchdoFZ3fWo2M2zIx+mpYuyt
# Hs+oznpktjOkf+zuYlOifT1J+eXazQ9UACBtOCGTd7hSx6YdN9sHVJi/pQ5PaY5s
# U9Int6Ln3njOxdmRQgx73T1Z87TXTJkDSZVTr5FPzOLstUqIf+FfbwiCPg90y9Zu
# TqWqCiW03MYxou76aSjyIthTv0H0ZWAnx+J5HYwXUTlbDtnbUftBhw+Hz1hnAtBM
# xGlorPQqiDiHjeapZWH+T60lqR5+Xv0fpYmOjv8CnVDvYO1dBnPYgtLH42Agmx+s
# Ms/rCHFMWcdfe/Sqo4oJTE80/jxPPwvY5PV/BkQ+3jYO+Nw9dnOVatdDwG5IDiRt
# olua5suATfvLOgYl5qBxPhG768Y0r27nZgVoiw+jRVijnR1oMe4DsTUjWImNu8tp
# aCnNFq5R6kXHl0pml07uclC24ZodX9tqbw4YMRbc4SdBMLTlLWPwAufHQV8MfsY4
# sl2wjg9T9++JgoHp+qH7lDzVb5Yq5laxHe6muP3trXhhhaceZAmasbEgC8hdEo37
# IrPfGWB+bP/3S1OA8YOW8L8lJOGT
# SIG # End signature block
