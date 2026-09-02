# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

function Update-Action1 {
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'Modify',
            'ModifyMembers', 
            'Delete'
        )]
        [String]$Action,
        [Parameter(Mandatory)]
        [ValidateSet(
            'EndpointGroup',
            'Endpoint',
            'Automation',
            'CustomAttribute',
            'RawURI'
        )]
        [string]$Type,
        [object]$Data,
        [string]$Id,
        [string]$AttributeName,
        [string]$AttributeValue,
        [string]$URI,
        [switch]$Force
    )
    Write-Action1Debug "Trying update for $Action => $Type."
    #Short out processing path if URI literal is specified.
    if ($Type -eq 'RawURI') {
        if (!$URI) {
             Write-Error "Error -URI value required when Action is type RawURI.`n"; 
             return $null 
        }
        else {
            return Invoke-Action1ApiRequest -Method PATCH -Path $URI -Body $Data -Label 'RawRequest' 
        } 
    }

    if (Initialize-Action1DefaultOrg) {
        $Org_ID = Get-Action1DefaultOrgId
    }

    switch ($Action) {
        'ModifyMembers' {
            switch ($Type) {
                'EndpointGroup' { 
                    $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap["U_GroupMembers"] -Org_ID $Org_ID -Object_ID $id)
                    return Invoke-Action1ApiRequest -Method POST -Path $Path -Body $Data -Label "$Action=>$Type"
                }
                default { Write-Error "Invalid request of $Type for query $Action." ; return $null }
            }
        }
        'Modify' {              
            if (!$Id) { Write-Error "When perfoming $Action=>$Type, the value for -Id must be specified to know what object to act on."; return $null } 
            switch ($Type) {
                'Automation' {
                    $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap["U_Automation"] -Org_ID $Org_ID -Object_Id $Id)
                    return Invoke-Action1ApiRequest -Method PATCH -Path $Path -Body $Data -Label "$Action=>$Type" 
                }
                'CustomAttribute' {
                    $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap["U_Endpoint"] -Org_ID $Org_ID -Object_Id $Id)
                    $Data = New-Object psobject -Property @{"custom:$AttributeName" = $AttributeValue }
                    return Invoke-Action1ApiRequest -Method PATCH -Path $Path -Body $Data -Label "$Action=>$Type" 
                }
                'Endpoint' { 
                    $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap["U_Endpoint"] -Org_ID $Org_ID -Object_Id $Id)
                    $Data.PSObject.Members | ForEach-Object { if (@('name', 'comment') -notcontains $_.Name) { $Data.PSObject.Members.Remove($_.Name) } }
                    return Invoke-Action1ApiRequest -Method PATCH -Path $Path -Body $Data -Label "$Action=>$Type" 
                }
                'EndpointGroup' { 
                    $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap["U_GroupModify"] -Org_ID $Org_ID -Object_Id $Id)
                    return Invoke-Action1ApiRequest -Method PATCH -Path $Path -Body $Data -Label "$Action=>$Type"
                }
                default { Write-Error "Invalid request of $Type for query $Action." ; return $null }
            }   
        }
        'Delete' {
            Write-Action1Debug "Force delete enabled:$Force."
            switch ($Type) {
                'EndpointGroup' { 
                    if ($force -or ((Read-Host "Are you sure you want to $Action $Type [$id]?`n[Y]es to confirm, any other key to cancel.") -eq 'Y')) {
                        $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap["U_GroupModify"] -Org_ID $Org_ID -Object_Id $Id)
                        return Invoke-Action1ApiRequest -Method DELETE -Path $Path -Label "$Action=>$Type"
                    }
                }
                'Endpoint' { 
                    if ($force -or ((Read-Host "Are you sure you want to $Action $Type [$id]?`n[Y]es to confirm, any other key to cancel.") -eq 'Y')) {
                        $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap["U_Endpoint"] -Org_ID $Org_ID -Object_Id $Id)
                        return Invoke-Action1ApiRequest -Method DELETE -Path $Path -Label "$Action=>$Type"
                    }
                }
                'Automation' {
                    if ($force -or ((Read-Host "Are you sure you want to $Action $Type [$id]?`n[Y]es to confirm, any other key to cancel.") -eq 'Y')) {
                        $Path = "$Script:Action1_BaseURI{0}" -f (& $Script:Action1_UriMap["U_Automation"] -Org_ID $Org_ID -Object_Id $Id)
                        return Invoke-Action1ApiRequest -Method DELETE -Path $Path -Label "$Action=>$Type"
                    }
                }
                default { Write-Error "Invalid request of $Type for query $Action." ; return $null }
            }
        }
        default { Write-Error "Invalid request of $Type for query $Action." ; return $null }
    }
}

# SIG # Begin signature block
# MII9NAYJKoZIhvcNAQcCoII9JTCCPSECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBMMOZdjox+4lKD
# PF/USfcta8WKOUnpGBdI9OXAPZNbH6CCIfYwggXMMIIDtKADAgECAhBUmNLR1FsZ
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
# 03u4aUoqlmZpxJTG9F9urJh4iIAGXKKy7aIwggaoMIIEkKADAgECAhMzAAWySwMZ
# qQI+y6nLAAAABbJLMA0GCSqGSIb3DQEBDAUAMFoxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDUyBBT0MgQ0EgMDQwHhcNMjYwODMxMjE0MDQwWhcNMjYwOTAz
# MjE0MDQwWjBrMQswCQYDVQQGEwJVUzEOMAwGA1UECBMFVGV4YXMxEDAOBgNVBAcT
# B0hvdXN0b24xHDAaBgNVBAoTE0FjdGlvbjEgQ29ycG9yYXRpb24xHDAaBgNVBAMT
# E0FjdGlvbjEgQ29ycG9yYXRpb24wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQDUWFekAr1l2sJJ3uSTQETiI+mE4CBpce9a/4sQgIGXMVM5cdRlNJCsyuiu
# puIRIaHPuKTU89Vx7rvpDkKG+2mLzCWOVrU490GYgjDy7OCv/ck8QOlgT0iOLr03
# I2b9v4pETc2QCdWDJm6BhS1be/VdOZtVBPwG2dgCfltquXBdfLGRWsTzDFKNE5wK
# ieL7SrSfOY9RZPFk3EivSbQXv8GP7EsLtD704Qn765+0+hYXJ/cQToeADQmF74L7
# Jvb4cekvb8++kWwRg+aQW0acIBQrYKUJC2ZT+FbPBN3ZnUmJr8nKMQXCG/vAmtaU
# gqjoMmJDCrOXSsaj4EoetpCSjcgZ+i0G6gfX1tw3hM06ZfXDZK8B51ZFC0RL9NHz
# e3k1iitG6de8moerMrGiFDHoRSXRL7yGZmUa6T1w5Bj9dkTuqd57P9jWOaV4k6ex
# fcBS6Sh8eBknS12gFUcZRhkcR4jMZciaIFW35fnLGbJTWXNpqa1afCgkDafP2qW7
# TgV2TpcCAwEAAaOCAdQwggHQMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeA
# MDsGA1UdJQQ0MDIGCisGAQQBgjdhAQAGCCsGAQUFBwMDBhorBgEEAYI3YYTGyjWC
# 84fIeoPTzfIboMPaLTAdBgNVHQ4EFgQUrFIZFNNHp3sn8bnjbbVYE3QcMsEwHwYD
# VR0jBBgwFoAUayVB3vtrfP0YgAotf492XapzPbgwZwYDVR0fBGAwXjBcoFqgWIZW
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# SUQlMjBWZXJpZmllZCUyMENTJTIwQU9DJTIwQ0ElMjAwNC5jcmwwdAYIKwYBBQUH
# AQEEaDBmMGQGCCsGAQUFBzAChlhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUyMEFPQyUy
# MENBJTIwMDQuY3J0MFQGA1UdIARNMEswSQYEVR0gADBBMD8GCCsGAQUFBwIBFjNo
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5o
# dG0wDQYJKoZIhvcNAQEMBQADggIBAIC0SNsr5142KKq3cuG/egQOqOIycF1U1abN
# JW5/G2bCMpOZgk6tMU4QnJAKhebD+M5G13VLs7J7Ct4+Qk7rcRYCGW94i1xceoAV
# Xo2a9GRRXhPwCPWYbsIK9+9BWkeKn8Ce9SXHm6h+geMAqxy5eQa/o8I8Ve+17YoY
# 5/dC9Qi7KumC36XnYHITgN3M/kD36FDINyI2ADBZTIAkWstwOUcL+6hqR73BiHU+
# Uht8GmQC7D5N+QJG6A0bG0wCzqloGWG6Pe2VcoAhry6OiwUkZoev44EeW5JKIrmO
# r6zl7AY2+YAdQdzG63zyrILJqHqDzK2oUmHeTF6pvgORwNpHmf5sFz79+sI0uep+
# hOvLpAagviTVfHa6NRTe1FIu72PSe90uRloAnTqsLG+TluqtX6XFMNW/Whif6rcZ
# tFO21nj8pbxtxNEGNzgSt93lCzq/PRvT9BFmexs+j3XkEP5ic/FmeWYpy7F0qmoU
# HX4d/YJgZidY2Ur5dbUng3HnMVZw9Mc4r939UllfESFpFIqz7qUrxBxxJG42/sUM
# bvFClzCzrOFpFCKvj0Y2V1xjtyOSH2f6P+spLD1/pnbRaZ/Vq3bzYYotg1z2xScz
# khg5LZwkj36P0ZMQlDQuG1TNq7NErIKwUkCMr+C/FsQLFbQoojja5SL4qtsYTdmg
# vIE38FeyMIIGqDCCBJCgAwIBAgITMwAFsksDGakCPsupywAAAAWySzANBgkqhkiG
# 9w0BAQwFADBaMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgSUQgVmVyaWZpZWQgQ1MgQU9DIENB
# IDA0MB4XDTI2MDgzMTIxNDA0MFoXDTI2MDkwMzIxNDA0MFowazELMAkGA1UEBhMC
# VVMxDjAMBgNVBAgTBVRleGFzMRAwDgYDVQQHEwdIb3VzdG9uMRwwGgYDVQQKExNB
# Y3Rpb24xIENvcnBvcmF0aW9uMRwwGgYDVQQDExNBY3Rpb24xIENvcnBvcmF0aW9u
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA1FhXpAK9ZdrCSd7kk0BE
# 4iPphOAgaXHvWv+LEICBlzFTOXHUZTSQrMrorqbiESGhz7ik1PPVce676Q5Chvtp
# i8wljla1OPdBmIIw8uzgr/3JPEDpYE9Iji69NyNm/b+KRE3NkAnVgyZugYUtW3v1
# XTmbVQT8BtnYAn5barlwXXyxkVrE8wxSjROcConi+0q0nzmPUWTxZNxIr0m0F7/B
# j+xLC7Q+9OEJ++uftPoWFyf3EE6HgA0Jhe+C+yb2+HHpL2/PvpFsEYPmkFtGnCAU
# K2ClCQtmU/hWzwTd2Z1Jia/JyjEFwhv7wJrWlIKo6DJiQwqzl0rGo+BKHraQko3I
# GfotBuoH19bcN4TNOmX1w2SvAedWRQtES/TR83t5NYorRunXvJqHqzKxohQx6EUl
# 0S+8hmZlGuk9cOQY/XZE7qneez/Y1jmleJOnsX3AUukofHgZJ0tdoBVHGUYZHEeI
# zGXImiBVt+X5yxmyU1lzaamtWnwoJA2nz9qlu04Fdk6XAgMBAAGjggHUMIIB0DAM
# BgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDA7BgNVHSUENDAyBgorBgEEAYI3
# YQEABggrBgEFBQcDAwYaKwYBBAGCN2GExso1gvOHyHqD083yG6DD2i0wHQYDVR0O
# BBYEFKxSGRTTR6d7J/G54221WBN0HDLBMB8GA1UdIwQYMBaAFGslQd77a3z9GIAK
# LX+Pdl2qcz24MGcGA1UdHwRgMF4wXKBaoFiGVmh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUy
# MEFPQyUyMENBJTIwMDQuY3JsMHQGCCsGAQUFBwEBBGgwZjBkBggrBgEFBQcwAoZY
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQl
# MjBJRCUyMFZlcmlmaWVkJTIwQ1MlMjBBT0MlMjBDQSUyMDA0LmNydDBUBgNVHSAE
# TTBLMEkGBFUdIAAwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMA0GCSqGSIb3DQEBDAUAA4IC
# AQCAtEjbK+deNiiqt3Lhv3oEDqjiMnBdVNWmzSVufxtmwjKTmYJOrTFOEJyQCoXm
# w/jORtd1S7OyewrePkJO63EWAhlveItcXHqAFV6NmvRkUV4T8Aj1mG7CCvfvQVpH
# ip/AnvUlx5uofoHjAKscuXkGv6PCPFXvte2KGOf3QvUIuyrpgt+l52ByE4DdzP5A
# 9+hQyDciNgAwWUyAJFrLcDlHC/uoake9wYh1PlIbfBpkAuw+TfkCRugNGxtMAs6p
# aBlhuj3tlXKAIa8ujosFJGaHr+OBHluSSiK5jq+s5ewGNvmAHUHcxut88qyCyah6
# g8ytqFJh3kxeqb4DkcDaR5n+bBc+/frCNLnqfoTry6QGoL4k1Xx2ujUU3tRSLu9j
# 0nvdLkZaAJ06rCxvk5bqrV+lxTDVv1oYn+q3GbRTttZ4/KW8bcTRBjc4Erfd5Qs6
# vz0b0/QRZnsbPo915BD+YnPxZnlmKcuxdKpqFB1+Hf2CYGYnWNlK+XW1J4Nx5zFW
# cPTHOK/d/VJZXxEhaRSKs+6lK8QccSRuNv7FDG7xQpcws6zhaRQir49GNldcY7cj
# kh9n+j/rKSw9f6Z20Wmf1at282GKLYNc9sUnM5IYOS2cJI9+j9GTEJQ0LhtUzauz
# RKyCsFJAjK/gvxbECxW0KKI42uUi+KrbGE3ZoLyBN/BXsjCCBygwggUQoAMCAQIC
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
# aC1ZOmBXiCRKJLj4DT2uhJ04ji+tHD6n58vhavFIrmcxghqUMIIakAIBATBxMFox
# CzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzAp
# BgNVBAMTIk1pY3Jvc29mdCBJRCBWZXJpZmllZCBDUyBBT0MgQ0EgMDQCEzMABbJL
# AxmpAj7LqcsAAAAFskswDQYJYIZIAWUDBAIBBQCgXjAQBgorBgEEAYI3AgEMMQIw
# ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAvBgkqhkiG9w0BCQQxIgQgCBgE
# ylAGEDFm8Yp2258JL1R598Uj31PrYBHohOdHtYcwDQYJKoZIhvcNAQEBBQAEggGA
# E7ERdE4I8Gpe2JIlzeHLrc2trSxjpmQJcSbmePYpJr+P7ZLWYQ10yV9ZvUt+10YB
# JKTHbyheSGGliKeu+MQYGjeAkHVEFhdh7RgUpVHGgymlFiD0Gr4oWSGK/Lfq6JDS
# 9MIu8g3nkyIWsbiJ9zRcnqfyMTliKNkl58VQ92iUScl6+UpMHsBpJLa+vRkSMvHt
# 4wToxBTsMUsKadlcE3ZBb1/mjgfndCq6yf++j+tVk1IgL1w7nbBXIVQ+Yv3U4N2q
# 2wRY1HHppaz1xgQGu8KfGd9MhCgGVOxFnzqX8Zpl9fsPpMjpGcyFJqHMIjzZxVZi
# ktC9ZRPFvTQaaNLLvYQgs7L61GAo4tRhDQPC3UuIN5/KIzN8BXNEZw0t9vvzveYm
# f2Gj1PQpBQDhwdt/DNNArV2AXNZN49vRMR5k4Z8H4L2+9A2/X+DTcWBXlIgXq4b3
# yGfQ1lUg6NeRAZawSbSVplfzKUZlktVKNzrkm3dZBV0nsvlc7dR5rc4LuBPwXiwZ
# oYIYFDCCGBAGCisGAQQBgjcDAwExghgAMIIX/AYJKoZIhvcNAQcCoIIX7TCCF+kC
# AQMxDzANBglghkgBZQMEAgEFADCCAWIGCyqGSIb3DQEJEAEEoIIBUQSCAU0wggFJ
# AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIJMMPt2W0HzGX/dkoasp
# ggDySKDIbyGjXaqi8OgcMTOxAgZqhEj4ioMYEzIwMjYwOTAyMTU1NTEyLjU0OVow
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
# AivorQ3Os8PELHIgiOd9TWzbdgmGzcILt/ddVQERMYIHRjCCB0ICAQEweDBhMQsw
# CQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYD
# VQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMAIT
# MwAAAFZ+j51YCI7pYAAAAAAAVjANBglghkgBZQMEAgEFAKCCBJ8wEQYLKoZIhvcN
# AQkQAg8xAgUAMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0B
# CQUxDxcNMjYwOTAyMTU1NTEyWjAvBgkqhkiG9w0BCQQxIgQglQT3asOmq3Mn41dV
# khh9+RG5hGvul69cm856PVBC2AwwgbkGCyqGSIb3DQEJEAIvMYGpMIGmMIGjMIGg
# BCC2DDMlTaTj8JV3iTg5Xnpe4CSH60143Z+X9o5NBgMMqDB8MGWkYzBhMQswCQYD
# VQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQD
# EylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMAITMwAA
# AFZ+j51YCI7pYAAAAAAAVjCCA2EGCyqGSIb3DQEJEAISMYIDUDCCA0yhggNIMIID
# RDCCAiwCAQEwggEJoYHhpIHeMIHbMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046QTUwMC0wNUUwLUQ5NDcxNTAzBgNV
# BAMTLE1pY3Jvc29mdCBQdWJsaWMgUlNBIFRpbWUgU3RhbXBpbmcgQXV0aG9yaXR5
# oiMKAQEwBwYFKw4DAhoDFQD/c/cpFSqQWYBeXggyRJ2ZbvYEEaBnMGWkYzBhMQsw
# CQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYD
# VQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMDAN
# BgkqhkiG9w0BAQsFAAIFAO5Cjd0wIhgPMjAyNjA5MDIxMTU4MjFaGA8yMDI2MDkw
# MzExNTgyMVowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA7kKN3QIBADAKAgEAAgIb
# nQIB/zAHAgEAAgIS9zAKAgUA7kPfXQIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgor
# BgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBCwUA
# A4IBAQAwA06ZYx7dtqtaGxVvzuK4pF1kuYwAksF7QPWE25jJ5AKnCjZk3ZUtdXOv
# GTZg6rfpSSOL3vDZiPraSC1MHQcd71U4SPc1GQP/JmEs9R8Axy5GNQYARNHcXerF
# e/zIoldDfYifcRpma0z0ALFmKaRjZpCT75NjbpKH+fsVZjygucu34JJd9FN5VJ14
# 2dDaumAHjuY2PSpBF2nXstBVeQj64NHGHb5Elno/+v1AZuQ7YljqfL3bWuXeEwwT
# avAv5HcueLjyInse44V/aWCDhG4bcvRrdzswum3oaS+X9FST1e1rysyG7SxRM26P
# zoGJK5h/v2HRHvN4opccHn1oL4IFMA0GCSqGSIb3DQEBAQUABIICACtsnn2pLQbh
# J8rgJRy62eBJ+jnlfhb7psqYzSlETNjv2GGpMd7l6OtG9iLs4MAL3xxCMlrRRYdJ
# 5UBfBHFsA5a2eatQvSNHcskJhAOQ4Pr6Wlrb+WWAHUNzc9jZuGWzKk4OWTfwqnsF
# Wbieg+T07l/PWMWg2wWffSY/elehvE8xmK+BudD2qJMsQsgbpz79DnWY7XX678gp
# qV7x76VT4e/LUihX6MYY1kXgEXzEvOaxJ+VDJKZ6FANg/xvEk/dDFVMxJoKGGEp3
# 52RMFCN5q4jwFkcLp8f9UK9WGUlN9TT7r98O+6HoqAX2/AxhJ4XdW96Us+Oy8Yqn
# gsqM5d4bDkhGZCM/FpOJ+10Qk9nagEIWTJlL/pieRcDfaA3IX3pfy/O+fmgWskgJ
# FAJ3Min6GlI75lNJLKY0dYgmAsNE+3dUoX34K7xu2LwekjCHPxiGh+hIIAgaphCC
# 7jca/ubmNr7aaWfsZPUdxapJQGpqNvgMJjovmUkKk7ZASPtc/eIfmZyBaJfxGGKa
# 4/pslXxY7nbrWseiqyl66dax/HtjVFlxA29QOgVMQBfGu+HtBRXHSlVd9/CaXaxT
# XelXhojenp4+BtGp1nJICtMr6VQC7DvyPWVVYUNmovQVylyBnLevTmKsoz+4S6gH
# QceBPGf4jTcTnmzHGWnEtSEzegrHiVTu
# SIG # End signature block
