# Name: PSAction1
# Description: Powershell module for working with the Action1 API.

# Documentation: https://github.com/Action1Corp/PSAction1/
# Use Action1 Roadmap system (https://roadmap.action1.com/) to submit feedback or enhancement requests.

# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

@{

    # Script module or binary module file associated with this manifest.
    RootModule        = 'PSAction1.psm1'

    # Version number of this module.
    ModuleVersion     = '1.6.9'

    # Supported PSEditions
    # CompatiblePSEditions = @()

    # ID used to uniquely identify this module
    GUID              = 'e5ede30e-11cd-442c-87f8-478d2ef0a4c0'

    # Author of this module
    Author            = 'Gene Moody'

    # Company or vendor of this module
    CompanyName       = 'Action1 Corporation'

    # Copyright statement for this module
    Copyright         = '(c) 2026 Action1 Corporation. All rights reserved.'

    # Description of the functionality provided by this module
    Description       = 'API Interface for Action1'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Name of the Windows PowerShell host required by this module
    # PowerShellHostName = ''

    # Minimum version of the Windows PowerShell host required by this module
    # PowerShellHostVersion = ''

    # Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # DotNetFrameworkVersion = ''

    # Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # CLRVersion = ''

    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''

    # Modules that must be imported into the global environment prior to importing this module
    # RequiredModules = @()

    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    # NestedModules = @()

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = 'Set-Action1Credentials', 
                        'Set-Action1DefaultOrg', 
                        'Set-Action1Locale',
                        'Set-Action1Region', 
                        'Set-Action1Debug', 
                        'New-Action1', 
                        'Get-Action1',
                        'Update-Action1',
                        'Set-Action1Interactive',
                        'Start-Action1Requery',
                        'Start-Action1PackageUpload'

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport   = '*'

    # Variables to export from this module
    VariablesToExport = '*'

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport   = '*'

    # DSC resources to export from this module
    # DscResourcesToExport = @()

    # List of all modules packaged with this module
    # ModuleList = @()

    # List of all files packaged with this module
    # FileList = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData       = @{

        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @('Action1')

            # A URL to the license for this module.
            # LicenseUri = ''

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/Action1Corp/PSAction1'

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            # ReleaseNotes = ''

        } # End of PSData hashtable

    } # End of PrivateData hashtable

    # HelpInfo URI of this module
    HelpInfoURI = ''

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''

}


# SIG # Begin signature block
# MII9NAYJKoZIhvcNAQcCoII9JTCCPSECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC+ATZGrnhWFOiZ
# PpmNP37rPRr0po+obDzBrsr7VOrh1qCCIfYwggXMMIIDtKADAgECAhBUmNLR1FsZ
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
# 03u4aUoqlmZpxJTG9F9urJh4iIAGXKKy7aIwggaoMIIEkKADAgECAhMzAAFBLsM2
# hq9VZ1bpAAAAAUEuMA0GCSqGSIb3DQEBDAUAMFoxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDUyBFT0MgQ0EgMDMwHhcNMjYwNTIxMTQxNjAyWhcNMjYwNTI0
# MTQxNjAyWjBrMQswCQYDVQQGEwJVUzEOMAwGA1UECBMFVGV4YXMxEDAOBgNVBAcT
# B0hvdXN0b24xHDAaBgNVBAoTE0FjdGlvbjEgQ29ycG9yYXRpb24xHDAaBgNVBAMT
# E0FjdGlvbjEgQ29ycG9yYXRpb24wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQCvZcTdtPDwx/lAE5WUaS/57cIw/dmMvk25IJ6rBQxggMK21gihEZcN0kmd
# SrplzExy4ps/8+nxtxPsmO+gaz41Etm7k5/og3xRBQ40M34eTdG8EGQDz9bOkLTU
# ZdkCHFLnqA8AL91gltZjq6WOdT/rsg6XeLva6TkhCSvgWMLWkjK8Dt2qYlqfRYhH
# AF4U9KbaVpfCG4pvAbDPC8GtWkQEC3w5fiNM+eJBEn0jh+/MNGzqPKwvj0RGYNuJ
# ML/CFsZCBMj3TmVEQ83KmW5P4GRKkQevyxIcmxSHeQQwweX7XE2Ae9M5UQdQECFe
# XkNzYDfGcQsPffrxt2kfPuaQOvcOZveJ1hteZAIp1BEa1WuERWIZVP9tiYpP98v3
# mf/kw4K84pq8+S+lfF37WOyC4BqH1m6nCxZXasAD6WRirElHYcTcow+14MVQVMYs
# q1NboAXFlE6UvG3PVO2rxz37/dTlPC4FKUnFzACNw4c4m65xag59Vsf/jaU5WLwx
# WW1V3QcCAwEAAaOCAdQwggHQMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeA
# MDsGA1UdJQQ0MDIGCisGAQQBgjdhAQAGCCsGAQUFBwMDBhorBgEEAYI3YYTGyjWC
# 84fIeoPTzfIboMPaLTAdBgNVHQ4EFgQUk/vFDrNjPPdtOBJQB09OzhnwJ24wHwYD
# VR0jBBgwFoAUa16lNMMFxWJKIVqOq3NgYtSsY4UwZwYDVR0fBGAwXjBcoFqgWIZW
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# SUQlMjBWZXJpZmllZCUyMENTJTIwRU9DJTIwQ0ElMjAwMy5jcmwwdAYIKwYBBQUH
# AQEEaDBmMGQGCCsGAQUFBzAChlhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUyMEVPQyUy
# MENBJTIwMDMuY3J0MFQGA1UdIARNMEswSQYEVR0gADBBMD8GCCsGAQUFBwIBFjNo
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5o
# dG0wDQYJKoZIhvcNAQEMBQADggIBACi8kN3goukTowT2yx7kxCKG9XehSulFN9+1
# yv0p+q2l4JOKO2SgTJ53SEN1JP7pimRK07GA/UapjlvYjRg4pJ3t+sBPa/BMcCn3
# bSC7iLPrJqRdi41xDT8Q9TS/dKlGc1IU0RKyfqBPFEi5UjZKPhdhPsVRTHVRbVJw
# oL8cmdV6bVZ/rG0zr1e4ARSSBpr9fep0H9zpXcWQgQVWHkR8NknBkX0LeATXqGKi
# 7GSx+z6fVesIgkIh6NaDa8KwHwSstwskhp+VeWo0+M677SSLgLJ4f1KtYoIK2HUY
# i+FWwzx8caWUjOIt92ufMXZksNdLb+RtRiuMsM4dwJ+iiKtHwKjoVXgS9tDxLrjU
# wZuFtRgOQXYKv2DZBL4wMR3vXARJNuXAet3BpUJSMOv4RxI4hmBw1RmoH8Xi4d9Z
# aLR7Fw85OXNpP0Xvr5badr+Wd98tk3V+Cwq6r4mfD1080aWmD4RapXbD78ewazxu
# LYRpP1OAAnUQySNGF8YdzUurBoVp+fFv54C5BKxTuuehu390QDSu/1ATx0H95qgZ
# 7CE9g4z3ZT9MHNEkrRijJCD9xlTheoi76GmKdYdEjIZSz2j48nEEjgBltSzjaQB9
# e+0X4FWxH20XcUtYQzhhX1itgrWWTT3DdvDvzUxrVpfuX3Fb9aD/UT4rdlIgX8O6
# 9RUtKYULMIIGqDCCBJCgAwIBAgITMwABQS7DNoavVWdW6QAAAAFBLjANBgkqhkiG
# 9w0BAQwFADBaMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgSUQgVmVyaWZpZWQgQ1MgRU9DIENB
# IDAzMB4XDTI2MDUyMTE0MTYwMloXDTI2MDUyNDE0MTYwMlowazELMAkGA1UEBhMC
# VVMxDjAMBgNVBAgTBVRleGFzMRAwDgYDVQQHEwdIb3VzdG9uMRwwGgYDVQQKExNB
# Y3Rpb24xIENvcnBvcmF0aW9uMRwwGgYDVQQDExNBY3Rpb24xIENvcnBvcmF0aW9u
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAr2XE3bTw8Mf5QBOVlGkv
# +e3CMP3ZjL5NuSCeqwUMYIDCttYIoRGXDdJJnUq6ZcxMcuKbP/Pp8bcT7JjvoGs+
# NRLZu5Of6IN8UQUONDN+Hk3RvBBkA8/WzpC01GXZAhxS56gPAC/dYJbWY6uljnU/
# 67IOl3i72uk5IQkr4FjC1pIyvA7dqmJan0WIRwBeFPSm2laXwhuKbwGwzwvBrVpE
# BAt8OX4jTPniQRJ9I4fvzDRs6jysL49ERmDbiTC/whbGQgTI905lREPNypluT+Bk
# SpEHr8sSHJsUh3kEMMHl+1xNgHvTOVEHUBAhXl5Dc2A3xnELD3368bdpHz7mkDr3
# Dmb3idYbXmQCKdQRGtVrhEViGVT/bYmKT/fL95n/5MOCvOKavPkvpXxd+1jsguAa
# h9ZupwsWV2rAA+lkYqxJR2HE3KMPteDFUFTGLKtTW6AFxZROlLxtz1Ttq8c9+/3U
# 5TwuBSlJxcwAjcOHOJuucWoOfVbH/42lOVi8MVltVd0HAgMBAAGjggHUMIIB0DAM
# BgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDA7BgNVHSUENDAyBgorBgEEAYI3
# YQEABggrBgEFBQcDAwYaKwYBBAGCN2GExso1gvOHyHqD083yG6DD2i0wHQYDVR0O
# BBYEFJP7xQ6zYzz3bTgSUAdPTs4Z8CduMB8GA1UdIwQYMBaAFGtepTTDBcViSiFa
# jqtzYGLUrGOFMGcGA1UdHwRgMF4wXKBaoFiGVmh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUy
# MEVPQyUyMENBJTIwMDMuY3JsMHQGCCsGAQUFBwEBBGgwZjBkBggrBgEFBQcwAoZY
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQl
# MjBJRCUyMFZlcmlmaWVkJTIwQ1MlMjBFT0MlMjBDQSUyMDAzLmNydDBUBgNVHSAE
# TTBLMEkGBFUdIAAwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMA0GCSqGSIb3DQEBDAUAA4IC
# AQAovJDd4KLpE6ME9sse5MQihvV3oUrpRTfftcr9KfqtpeCTijtkoEyed0hDdST+
# 6YpkStOxgP1GqY5b2I0YOKSd7frAT2vwTHAp920gu4iz6yakXYuNcQ0/EPU0v3Sp
# RnNSFNESsn6gTxRIuVI2Sj4XYT7FUUx1UW1ScKC/HJnVem1Wf6xtM69XuAEUkgaa
# /X3qdB/c6V3FkIEFVh5EfDZJwZF9C3gE16hiouxksfs+n1XrCIJCIejWg2vCsB8E
# rLcLJIaflXlqNPjOu+0ki4CyeH9SrWKCCth1GIvhVsM8fHGllIziLfdrnzF2ZLDX
# S2/kbUYrjLDOHcCfooirR8Co6FV4EvbQ8S641MGbhbUYDkF2Cr9g2QS+MDEd71wE
# STblwHrdwaVCUjDr+EcSOIZgcNUZqB/F4uHfWWi0excPOTlzaT9F76+W2na/lnff
# LZN1fgsKuq+Jnw9dPNGlpg+EWqV2w+/HsGs8bi2EaT9TgAJ1EMkjRhfGHc1LqwaF
# afnxb+eAuQSsU7rnobt/dEA0rv9QE8dB/eaoGewhPYOM92U/TBzRJK0YoyQg/cZU
# 4XqIu+hpinWHRIyGUs9o+PJxBI4AZbUs42kAfXvtF+BVsR9tF3FLWEM4YV9YrYK1
# lk09w3bw781Ma1aX7l9xW/Wg/1E+K3ZSIF/DuvUVLSmFCzCCBygwggUQoAMCAQIC
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
# aC1ZOmBXiCRKJLj4DT2uhJ04ji+tHD6n58vhavFIrmcxghqUMIIakAIBATBxMFox
# CzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzAp
# BgNVBAMTIk1pY3Jvc29mdCBJRCBWZXJpZmllZCBDUyBFT0MgQ0EgMDMCEzMAAUEu
# wzaGr1VnVukAAAABQS4wDQYJYIZIAWUDBAIBBQCgXjAQBgorBgEEAYI3AgEMMQIw
# ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAvBgkqhkiG9w0BCQQxIgQgFbgc
# dj2w0lZMLlPowpq355ef8fGPZ9Y4OiciP9VHsSgwDQYJKoZIhvcNAQEBBQAEggGA
# mWan0QP7TmlyvNmeck1eQTjMG8SMsmduAQSSLszHF+iBdmwszbH9eQH7VQ66AVD7
# gcAixthYPZgPFVg8eeZIOyqDJwzTzCNESAXp3Ggv5ldiKFgn5bxsBFjf5BtQQzAk
# webdMcIiUDEZ+bCZMlZxk44CoMDzbdXO8BY46IGTXuVLDGTAxjpGStwt0/EIkBwK
# Sf0ZRtFEKZidBcCKb8jmfbnwgNOcXLV+kLkp6xWPVHREgd5n/tjFxZveQXdbaPFn
# 8x/6pmneaJ72qkRucvecbwS97/m+n0dRDmkLuFgug2x0WOrHbRoy51ZLgMM3t2wK
# nkYms5wuT0sXysRymFII/H1+E3pQ4rOs9CDV4cZeVS3hYE8qgKUBa4URgKZZX8Dn
# 0e3OSVZSOLWVztTNtuFlKgh4Bjn8bFDv7o2TmkA4YBBDmwodwXq+R1JyrhllwqGb
# rR8EQqIteKSqSXZ9ZYdSVP46qq3taj3FFI6rZDzG/DiM9FPe6pedwegt/eADgcYw
# oYIYFDCCGBAGCisGAQQBgjcDAwExghgAMIIX/AYJKoZIhvcNAQcCoIIX7TCCF+kC
# AQMxDzANBglghkgBZQMEAgEFADCCAWIGCyqGSIb3DQEJEAEEoIIBUQSCAU0wggFJ
# AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIDzTmv8fsYqnAjv0juge
# aAx1V/5WQOLoUkzkWZgSrIJWAgZp6IE48t8YEzIwMjYwNTIxMTczMzM3LjA3Mlow
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
# CG/uR5tK5rW6mZH5Oq56UWS0NI6NV1JGS7Jri6jFMYIHRjCCB0ICAQEweDBhMQsw
# CQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYD
# VQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMAIT
# MwAAAFXZ3WkmKPn44gAAAAAAVTANBglghkgBZQMEAgEFAKCCBJ8wEQYLKoZIhvcN
# AQkQAg8xAgUAMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0B
# CQUxDxcNMjYwNTIxMTczMzM3WjAvBgkqhkiG9w0BCQQxIgQgJK2631eRxZ7aWGu0
# L3KIHjFeCm3W8Hhc2D82V7o5+oYwgbkGCyqGSIb3DQEJEAIvMYGpMIGmMIGjMIGg
# BCDYuTyXZIZiu799/v4PaqsmeSzBxh0rqkYq7sYYavj+zTB8MGWkYzBhMQswCQYD
# VQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQD
# EylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMAITMwAA
# AFXZ3WkmKPn44gAAAAAAVTCCA2EGCyqGSIb3DQEJEAISMYIDUDCCA0yhggNIMIID
# RDCCAiwCAQEwggEJoYHhpIHeMIHbMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046N0QwMC0wNUUwLUQ5NDcxNTAzBgNV
# BAMTLE1pY3Jvc29mdCBQdWJsaWMgUlNBIFRpbWUgU3RhbXBpbmcgQXV0aG9yaXR5
# oiMKAQEwBwYFKw4DAhoDFQAdO1QBgmW/tuBZV5EGjhfsV4cN6qBnMGWkYzBhMQsw
# CQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYD
# VQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMDAN
# BgkqhkiG9w0BAQsFAAIFAO25OvAwIhgPMjAyNjA1MjEwODA0MDBaGA8yMDI2MDUy
# MjA4MDQwMFowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA7bk68AIBADAKAgEAAgIa
# DgIB/zAHAgEAAgISqDAKAgUA7bqMcAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgor
# BgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBCwUA
# A4IBAQCICSHSIuaxOenS2KlJgAyygdUgu3w7nS8XrtchXg6VdbyXnRYlu3MpMjuG
# bUtRkHFJX4gxIVsS0pEmbuqwbnTIKE0qQwqKAJ6brR967DrVYoNRYlXPkrKsEk3N
# oi/FOFi5G415msCFHNQxqaPeFi3BNQUCh+stgbHmUOs+c6jDYwTvpn3w90otT+Dw
# oLG00uZNYXzmFJ/cBCYnN6UDDeM0i8qXbg/sL4JM3SyVxsgBg6Bl4+uAX/xddHmE
# 15QISc2ugBHbowTHNL+GIQmBF71fGe6gjag0mPpCswp+w2cF2QkeoX8J7c4R1FoB
# CcJRqE23yQaD5EpWYbxxFJX3yUPKMA0GCSqGSIb3DQEBAQUABIICAKttYx16H2qy
# Ei2KWhNSwbbpmQ4etKBMoQvuuwhCissHmEVCla+qq4SHvyAu6v+sGZSBcwSPSIUL
# vY3ta8uXCUqu85Z7V5kN17hn2PU/l0IuCkr8qqYPdyp5jScAHyHnq4NGNtDFK9VC
# TTllugqkjoTEoa4KfZyuTjCcwRV5VG3jKCCCaVou/H0a6QZtkGrnV5ajVhodUWtm
# 3B/YTfdkgi39YYIJ/i1TSVa+v4+d/pSo/CCSb2UIZeMwpquSX7WIdK6djf8WyLRD
# Ep4wFOOgOkWy09wXyY92++ptiDUWIXZQtialA1qfn/5ALE+oSxe4HA2h6+5r/hsk
# 4DeAJmkWOAu/7de2lCk8DPV+c1l35ufh+rbhJ9p2MLovjAtzqa7dWiMY/WW+7ZN1
# AqAKSIe34YC3N5sIZ5DkhERlXVZD1qKGWiOcjIiwjjBLlK3X8edwQw56ABt6lih8
# mqVQK1vTMe7chG9TmJuVttHDbaJRaPqmgLNiRfZfugOxHxblZsS2v2pRhFA6Xue2
# Uxo7FDqssWC1hTfqi4hoG0Gu0w0KTdA3exv6KfoE0VWTsmSGSizmZIV65d8kJxky
# vA7zQp22M+q23Iz29ApYNya3HZTbdt1eIQJidH9Q/26nFL8my4MrTn5TWP3Drx/P
# 4HfYYa9fCuNedjjGt0a+tUbKJAxd3+v3
# SIG # End signature block
