# Name: PSAction1
# Description: Powershell module for working with the Aciton1 API.
# Copyright (C) 2026 Action1 Corporation
# Documentation: https://github.com/Action1Corp/PSAction1/
# Use Action1 Roadmap system (https://roadmap.action1.com/) to submit feedback or enhancement requests.

# WARNING: Carefully study the provided scripts and components before using them. Test in your non-production lab first.

# LIMITATION OF LIABILITY. IN NO EVENT SHALL ACTION1 OR ITS SUPPLIERS, OR THEIR RESPECTIVE 
# OFFICERS, DIRECTORS, EMPLOYEES, OR AGENTS BE LIABLE WITH RESPECT TO THE WEBSITE OR
# THE COMPONENTS OR THE SERVICES UNDER ANY CONTRACT, NEGLIGENCE, TORT, STRICT 
# LIABILITY OR OTHER LEGAL OR EQUITABLE THEORY (I)FOR ANY AMOUNT IN THE AGGREGATE IN
# EXCESS OF THE GREATER OF FEES PAID BY YOU THEREFOR OR $100; (II) FOR ANY INDIRECT,
# INCIDENTAL, PUNITIVE, OR CONSEQUENTIAL DAMAGES OF ANY KIND WHATSOEVER; (III) FOR
# DATA LOSS OR COST OF PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; OR (IV) FOR ANY
# MATTER BEYOND ACTION1’S REASONABLE CONTROL. SOME STATES DO NOT ALLOW THE
# EXCLUSION OR LIMITATION OF INCIDENTAL OR CONSEQUENTIAL DAMAGES, SO THE ABOVE
# LIMITATIONS AND EXCLUSIONS MAY NOT APPLY TO YOU.

@{

    # Script module or binary module file associated with this manifest.
    RootModule        = 'PSAction1.psm1'

    # Version number of this module.
    ModuleVersion     = '1.5.8'

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
# MII96wYJKoZIhvcNAQcCoII93DCCPdgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCNuYvmHhFlMQSr
# L3ImsfAWR1jgeHyBXkzWqL2bRl7jGqCCIrAwggXMMIIDtKADAgECAhBUmNLR1FsZ
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
# 03u4aUoqlmZpxJTG9F9urJh4iIAGXKKy7aIwggbsMIIE1KADAgECAhMzAAe8E8Zf
# DI+rQz3HAAAAB7wTMA0GCSqGSIb3DQEBDAUAMFoxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDUyBFT0MgQ0EgMDEwHhcNMjYwMzMwMTQyNTU2WhcNMjYwNDAy
# MTQyNTU2WjBrMQswCQYDVQQGEwJVUzEOMAwGA1UECBMFVGV4YXMxEDAOBgNVBAcT
# B0hvdXN0b24xHDAaBgNVBAoTE0FjdGlvbjEgQ29ycG9yYXRpb24xHDAaBgNVBAMT
# E0FjdGlvbjEgQ29ycG9yYXRpb24wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQDeg9jgofFKtvzL98o6wjb4aX22nes3kl1fQ0r0MSz6/MCRwqt97uMjLlbl
# UAsolSHOsXsBpnU8ElPLkEBQ8qAXYzwQRJVm64AgmxI24x9NwQOtp7v4Tz2EMXbE
# Kafoeq9CoOvLFLvFhAYzkAA+3NgePIEKQuqJ9nmuF7vq7qFIKA/G9GNQgIZwz0x5
# yISkpeuuXavOK6KubpFmRiyrIAbOM6EJgaxwksQ336yJFDiTixL4SPZQf0hOWFz9
# +iHV4Y/nu9htc31mMuTGmrnp2ayoSG+dJv7U1jlrtnefv+LPHZAZgOStzruuPMmi
# M/p5sz1FoAYDVjUxpne3RPoRuLkrda4TR1NsbKbNHXU20zI5VlVnSuzv2C4sL/g8
# DHRQKOC93OWvXMhFBP7tLNxDG6Jlf7LDzdtNd0AF3ZSjGcAWlg9/Q/7PY02hoL2+
# plvavNaMFcupOCI13ce6H8iqLk0BQzAc9Inv8IWioIAdBIYODqp2xhXZD1FzDQ08
# uOhPGI8CAwEAAaOCAhgwggIUMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeA
# MDsGA1UdJQQ0MDIGCisGAQQBgjdhAQAGCCsGAQUFBwMDBhorBgEEAYI3YYTGyjWC
# 84fIeoPTzfIboMPaLTAdBgNVHQ4EFgQUIESqFE7zJAZYSTNy+nGAB88ORb4wHwYD
# VR0jBBgwFoAUdpw2dBPRkH1hX7MC64D0mUulPoUwZwYDVR0fBGAwXjBcoFqgWIZW
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# SUQlMjBWZXJpZmllZCUyMENTJTIwRU9DJTIwQ0ElMjAwMS5jcmwwgaUGCCsGAQUF
# BwEBBIGYMIGVMGQGCCsGAQUFBzAChlhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUyMEVP
# QyUyMENBJTIwMDEuY3J0MC0GCCsGAQUFBzABhiFodHRwOi8vb25lb2NzcC5taWNy
# b3NvZnQuY29tL29jc3AwZgYDVR0gBF8wXTBRBgwrBgEEAYI3TIN9AQEwQTA/Bggr
# BgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1Jl
# cG9zaXRvcnkuaHRtMAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAWVgkSIxU
# bv74c+PUvtgyyEzCcclNRdI09jvtsdoiZXhTAXEL6JbzIROoBgWeBYG86sKn9O5+
# X/VDFedVP/Q12aL7z9M47gHYhHUAAeSyc7gZ4ETt7lBzjMB0LOqtQ+QFJbaktr6l
# y9il9JWLJtav2G49+yo16CP9KruHA/lWLYX3FGd3ohpWluEAprkHExc5y/ajy9Q5
# GhcwSrfpLLgI60ZpzgXt7yHRJ6XnsMWgrdlEmpjfku7f+RlDliSUW3S0XdVdrWuI
# cumGharz66ZSIadl8zgBlWxTa7i8PUrd5PHlXLf5/4rC7Dx+46ceS4r+lKsvycFT
# 3LehcQwZLHxBbGiPkUMB3OSnMJOmMo256YAuqzblzeNfUi8ZBShQ+aldljZQTh8E
# hA5f7TI8WdmmmVTszsCv7sH0pgWLjigxYqxrmKNSCDZvGPW9qc6JO4Gl11hmbi7x
# mb8+WYgUH571jf36mr9id2ofXxuevMRVJWkU3cLyWPr8Oule7WJfkeTxovJK2q49
# JOnO0HTqbFe+MUWEmmDd2Zxvv0Vfz6pCwAZnFjux4aCTI3CD6ywlRGdkiYQO0TpS
# dbD9SZCmRnarH3TJZM/ee259u7NmkTAOlGTFO6zGO5N5MyPUketn8EdlZPc+VprO
# IAlKQizzEFqUKL5nNFXcjr1/xxSU4/pcIQAwggbsMIIE1KADAgECAhMzAAe8E8Zf
# DI+rQz3HAAAAB7wTMA0GCSqGSIb3DQEBDAUAMFoxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDUyBFT0MgQ0EgMDEwHhcNMjYwMzMwMTQyNTU2WhcNMjYwNDAy
# MTQyNTU2WjBrMQswCQYDVQQGEwJVUzEOMAwGA1UECBMFVGV4YXMxEDAOBgNVBAcT
# B0hvdXN0b24xHDAaBgNVBAoTE0FjdGlvbjEgQ29ycG9yYXRpb24xHDAaBgNVBAMT
# E0FjdGlvbjEgQ29ycG9yYXRpb24wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQDeg9jgofFKtvzL98o6wjb4aX22nes3kl1fQ0r0MSz6/MCRwqt97uMjLlbl
# UAsolSHOsXsBpnU8ElPLkEBQ8qAXYzwQRJVm64AgmxI24x9NwQOtp7v4Tz2EMXbE
# Kafoeq9CoOvLFLvFhAYzkAA+3NgePIEKQuqJ9nmuF7vq7qFIKA/G9GNQgIZwz0x5
# yISkpeuuXavOK6KubpFmRiyrIAbOM6EJgaxwksQ336yJFDiTixL4SPZQf0hOWFz9
# +iHV4Y/nu9htc31mMuTGmrnp2ayoSG+dJv7U1jlrtnefv+LPHZAZgOStzruuPMmi
# M/p5sz1FoAYDVjUxpne3RPoRuLkrda4TR1NsbKbNHXU20zI5VlVnSuzv2C4sL/g8
# DHRQKOC93OWvXMhFBP7tLNxDG6Jlf7LDzdtNd0AF3ZSjGcAWlg9/Q/7PY02hoL2+
# plvavNaMFcupOCI13ce6H8iqLk0BQzAc9Inv8IWioIAdBIYODqp2xhXZD1FzDQ08
# uOhPGI8CAwEAAaOCAhgwggIUMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeA
# MDsGA1UdJQQ0MDIGCisGAQQBgjdhAQAGCCsGAQUFBwMDBhorBgEEAYI3YYTGyjWC
# 84fIeoPTzfIboMPaLTAdBgNVHQ4EFgQUIESqFE7zJAZYSTNy+nGAB88ORb4wHwYD
# VR0jBBgwFoAUdpw2dBPRkH1hX7MC64D0mUulPoUwZwYDVR0fBGAwXjBcoFqgWIZW
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# SUQlMjBWZXJpZmllZCUyMENTJTIwRU9DJTIwQ0ElMjAwMS5jcmwwgaUGCCsGAQUF
# BwEBBIGYMIGVMGQGCCsGAQUFBzAChlhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUyMEVP
# QyUyMENBJTIwMDEuY3J0MC0GCCsGAQUFBzABhiFodHRwOi8vb25lb2NzcC5taWNy
# b3NvZnQuY29tL29jc3AwZgYDVR0gBF8wXTBRBgwrBgEEAYI3TIN9AQEwQTA/Bggr
# BgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1Jl
# cG9zaXRvcnkuaHRtMAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAWVgkSIxU
# bv74c+PUvtgyyEzCcclNRdI09jvtsdoiZXhTAXEL6JbzIROoBgWeBYG86sKn9O5+
# X/VDFedVP/Q12aL7z9M47gHYhHUAAeSyc7gZ4ETt7lBzjMB0LOqtQ+QFJbaktr6l
# y9il9JWLJtav2G49+yo16CP9KruHA/lWLYX3FGd3ohpWluEAprkHExc5y/ajy9Q5
# GhcwSrfpLLgI60ZpzgXt7yHRJ6XnsMWgrdlEmpjfku7f+RlDliSUW3S0XdVdrWuI
# cumGharz66ZSIadl8zgBlWxTa7i8PUrd5PHlXLf5/4rC7Dx+46ceS4r+lKsvycFT
# 3LehcQwZLHxBbGiPkUMB3OSnMJOmMo256YAuqzblzeNfUi8ZBShQ+aldljZQTh8E
# hA5f7TI8WdmmmVTszsCv7sH0pgWLjigxYqxrmKNSCDZvGPW9qc6JO4Gl11hmbi7x
# mb8+WYgUH571jf36mr9id2ofXxuevMRVJWkU3cLyWPr8Oule7WJfkeTxovJK2q49
# JOnO0HTqbFe+MUWEmmDd2Zxvv0Vfz6pCwAZnFjux4aCTI3CD6ywlRGdkiYQO0TpS
# dbD9SZCmRnarH3TJZM/ee259u7NmkTAOlGTFO6zGO5N5MyPUketn8EdlZPc+VprO
# IAlKQizzEFqUKL5nNFXcjr1/xxSU4/pcIQAwggdaMIIFQqADAgECAhMzAAAABkoa
# +s8FYWp0AAAAAAAGMA0GCSqGSIb3DQEBDAUAMGMxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xNDAyBgNVBAMTK01pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDb2RlIFNpZ25pbmcgUENBIDIwMjEwHhcNMjEwNDEzMTczMTU0
# WhcNMjYwNDEzMTczMTU0WjBaMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgSUQgVmVyaWZpZWQg
# Q1MgRU9DIENBIDAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAx+PI
# P/Qh3cYZwLvFy6uuJ4fTp3ln7Gqs7s8lTVyfgOJWP1aABwk2/oxdVjfSHUq4MTPX
# ilL57qi/fH7YndEK4Knd3u5cedFwr2aHSTp6vl/PL1dAL9sfoDvNpdG0N/R84AhY
# NpBQThpO4/BqxmCgl3iIRfhh2oFVOuiTiDVWvXBg76bcjnHnEEtXzvAWwJu0bBU7
# oRRqQed4VXJtICVt+ZoKUSjqY5wUlhAdwHh+31BnpBPCzFtKViLp6zEtRyOxRega
# gFU+yLgXvvmd07IDN0S2TLYuiZjTw+kcYOtoNgKr7k0C6E9Wf3H4jHavk2MxqFpt
# gfL0gL+zbSb+VBNKiVT0mqzXJIJmWmqw0K+D3MKfmCer3e3CbrP+F5RtCb0XaE0u
# RcJPZJjWwciDBxBIbkNF4GL12hl5vydgFMmzQcNuodKyX//3lLJ1q22roHVS1cgt
# sLgpjWYZlBlhCTcXJeZ3xuaJvXZB9rcLCX15OgXL21tUUwJCLE27V5AGZxkO3i54
# mgSCswtOmWU4AKd/B/e3KtXv6XBURKuAteez1EpgloaZwQej9l5dN9Uh8W19BZg9
# IlLl+xHRX4vDiMWAUf/7ANe4MoS98F45r76IGJ0hC02EMuMZxAErwZj0ln0aL53E
# zlMa5JCiRObb0UoLHfGSdNJsMg0uj3DAQDdVWTECAwEAAaOCAg4wggIKMA4GA1Ud
# DwEB/wQEAwIBhjAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQUdpw2dBPRkH1h
# X7MC64D0mUulPoUwVAYDVR0gBE0wSzBJBgRVHSAAMEEwPwYIKwYBBQUHAgEWM2h0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0
# bTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTASBgNVHRMBAf8ECDAGAQH/AgEA
# MB8GA1UdIwQYMBaAFNlBKbAPD2Ns72nX9c0pnqRIajDmMHAGA1UdHwRpMGcwZaBj
# oGGGX2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29m
# dCUyMElEJTIwVmVyaWZpZWQlMjBDb2RlJTIwU2lnbmluZyUyMFBDQSUyMDIwMjEu
# Y3JsMIGuBggrBgEFBQcBAQSBoTCBnjBtBggrBgEFBQcwAoZhaHR0cDovL3d3dy5t
# aWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBJRCUyMFZlcmlm
# aWVkJTIwQ29kZSUyMFNpZ25pbmclMjBQQ0ElMjAyMDIxLmNydDAtBggrBgEFBQcw
# AYYhaHR0cDovL29uZW9jc3AubWljcm9zb2Z0LmNvbS9vY3NwMA0GCSqGSIb3DQEB
# DAUAA4ICAQBqLwmf2LB1QjUga0G7zFkbGd8NBQLHP0KOFBWNJFZiTtKfpO0bZ2Wf
# s6v5vqIKjE32Q6M89G4ZkVcvWuEAA+dvjLThSy89Y0//m/WTSKwYtiR1Ewn7x1kw
# /Fg93wQps2C1WUj+00/6uNrF+d4MVJxV1HoBID+95ZIW0KkqZopnOA4w5vP4T5cB
# prZQAlP/vMGyB0H9+pHNo0jT9Q8gfKJNzHS9i1DgBmmufGdW9TByuno8GAizFMhL
# lIs08b5lilIkE5z3FMAUAr+XgII1FNZnb43OI6Qd2zOijbjYfursXUCNHC+RSwJG
# m5ULzPymYggnJ+khJOq7oSlqPGpbr70hGBePw/J7/mmSqp7hTgt0mPikS1i4ap8x
# +P3yemYShnFrgV1752TI+As69LfgLthkITvf7bFHB8vmIhadZCOS0vTCx3B+/OVc
# EMLNO2bJ0O9ikc1JqR0Fvqx7nAwMRSh3FVqosgzBbWnVkQJq7oWFwMVfFIYn6LPR
# ZMt48u6iMUCFBSPddsPA/6k85mEv+08U5WCQ7ydj1KVV2THre/8mLHiem9wf/Czo
# hqRntxM2E/x+NHy6TBMnSPQRqhhNfuOgUDAWEYmlM/ZHGaPIb7xOvfVyLQ/7l6Yf
# ogT3eptwp4GOGRjH5z+gG9kpBIx8QrRl6OilnlxRExokmMflL7l12TCCB54wggWG
# oAMCAQICEzMAAAAHh6M0o3uljhwAAAAAAAcwDQYJKoZIhvcNAQEMBQAwdzELMAkG
# A1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjFIMEYGA1UE
# AxM/TWljcm9zb2Z0IElkZW50aXR5IFZlcmlmaWNhdGlvbiBSb290IENlcnRpZmlj
# YXRlIEF1dGhvcml0eSAyMDIwMB4XDTIxMDQwMTIwMDUyMFoXDTM2MDQwMTIwMTUy
# MFowYzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjE0MDIGA1UEAxMrTWljcm9zb2Z0IElEIFZlcmlmaWVkIENvZGUgU2lnbmluZyBQ
# Q0EgMjAyMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALLwwK8ZiCji
# 3VR6TElsaQhVCbRS/3pK+MHrJSj3Zxd3KU3rlfL3qrZilYKJNqztA9OQacr1AwoN
# cHbKBLbsQAhBnIB34zxf52bDpIO3NJlfIaTE/xrweLoQ71lzCHkD7A4As1Bs076I
# u+mA6cQzsYYH/Cbl1icwQ6C65rU4V9NQhNUwgrx9rGQ//h890Q8JdjLLw0nV+ayQ
# 2Fbkd242o9kH82RZsH3HEyqjAB5a8+Ae2nPIPc8sZU6ZE7iRrRZywRmrKDp5+Tcm
# JX9MRff241UaOBs4NmHOyke8oU1TYrkxh+YeHgfWo5tTgkoSMoayqoDpHOLJs+qG
# 8Tvh8SnifW2Jj3+ii11TS8/FGngEaNAWrbyfNrC69oKpRQXY9bGH6jn9NEJv9weF
# xhTwyvx9OJLXmRGbAUXN1U9nf4lXezky6Uh/cgjkVd6CGUAf0K+Jw+GE/5VpIVbc
# Nr9rNE50Sbmy/4RTCEGvOq3GhjITbCa4crCzTTHgYYjHs1NbOc6brH+eKpWLtr+b
# Gecy9CrwQyx7S/BfYJ+ozst7+yZtG2wR461uckFu0t+gCwLdN0A6cFtSRtR8bvxV
# FyWwTtgMMFRuBa3vmUOTnfKLsLefRaQcVTgRnzeLzdpt32cdYKp+dhr2ogc+qM6K
# 4CBI5/j4VFyC4QFeUP2YAidLtvpXRRo3AgMBAAGjggI1MIICMTAOBgNVHQ8BAf8E
# BAMCAYYwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNlBKbAPD2Ns72nX9c0p
# nqRIajDmMFQGA1UdIARNMEswSQYEVR0gADBBMD8GCCsGAQUFBwIBFjNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wGQYJ
# KwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSME
# GDAWgBTIftJqhSobyhmYBAcnz1AQT2ioojCBhAYDVR0fBH0wezB5oHegdYZzaHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwSWRl
# bnRpdHklMjBWZXJpZmljYXRpb24lMjBSb290JTIwQ2VydGlmaWNhdGUlMjBBdXRo
# b3JpdHklMjAyMDIwLmNybDCBwwYIKwYBBQUHAQEEgbYwgbMwgYEGCCsGAQUFBzAC
# hnVodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29m
# dCUyMElkZW50aXR5JTIwVmVyaWZpY2F0aW9uJTIwUm9vdCUyMENlcnRpZmljYXRl
# JTIwQXV0aG9yaXR5JTIwMjAyMC5jcnQwLQYIKwYBBQUHMAGGIWh0dHA6Ly9vbmVv
# Y3NwLm1pY3Jvc29mdC5jb20vb2NzcDANBgkqhkiG9w0BAQwFAAOCAgEAfyUqnv7U
# q+rdZgrbVyNMul5skONbhls5fccPlmIbzi+OwVdPQ4H55v7VOInnmezQEeW4LqK0
# wja+fBznANbXLB0KrdMCbHQpbLvG6UA/Xv2pfpVIE1CRFfNF4XKO8XYEa3oW8oVH
# +KZHgIQRIwAbyFKQ9iyj4aOWeAzwk+f9E5StNp5T8FG7/VEURIVWArbAzPt9ThVN
# 3w1fAZkF7+YU9kbq1bCR2YD+MtunSQ1Rft6XG7b4e0ejRA7mB2IoX5hNh3UEauY0
# byxNRG+fT2MCEhQl9g2i2fs6VOG19CNep7SquKaBjhWmirYyANb0RJSLWjinMLXN
# OAga10n8i9jqeprzSMU5ODmrMCJE12xS/NWShg/tuLjAsKP6SzYZ+1Ry358ZTFcx
# 0FS/mx2vSoU8s8HRvy+rnXqyUJ9HBqS0DErVLjQwK8VtsBdekBmdTbQVoCgPCqr+
# PDPB3xajYnzevs7eidBsM71PINK2BoE2UfMwxCCX3mccFgx6UsQeRSdVVVNSyALQ
# e6PT12418xon2iDGE81OGCreLzDcMAZnrUAx4XQLUz6ZTl65yPUiOh3k7Yww94lD
# f+8oG2oZmDh5O1Qe38E+M3vhKwmzIeoB1dVLlz4i3IpaDcR+iuGjH2TdaC1ZOmBX
# iCRKJLj4DT2uhJ04ji+tHD6n58vhavFIrmcxghqRMIIajQIBATBxMFoxCzAJBgNV
# BAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMT
# Ik1pY3Jvc29mdCBJRCBWZXJpZmllZCBDUyBFT0MgQ0EgMDECEzMAB7wTxl8Mj6tD
# PccAAAAHvBMwDQYJYIZIAWUDBAIBBQCgXjAQBgorBgEEAYI3AgEMMQIwADAZBgkq
# hkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAvBgkqhkiG9w0BCQQxIgQgy2BePeXKX/QJ
# JW1rV7yu5zYHEcipnpCyb6aueSos1EEwDQYJKoZIhvcNAQEBBQAEggGASj5Ctd/F
# 9LIzRC0sRHX+pB2keTpsKS5wBQ6Id9OYz3m6mfcuqT3niE5fZxT0pmQK42+/X5gv
# gNnnU92ne9rFbIs6Jh5155u3RZ0F6yN7xYrBYtFxgoDbH/uYCdiItRByox7TPFrp
# B9MAmncI2IDTVNY7u4YKlZylfP2sXYKwt794eADd0C0Dseu+YCNLHtuRmxru2pQz
# PLusqJkBf+g0ZjtWGPyZ15Y+a7wU+fQqTTD/qEJGGmD5lpIJfk00APvGm4O3yBOO
# Cs+Y4OSh96Xf3xltTBwpUMLlFRroqPR5DgW/hC2UySdVFDRGr+0o/Wr31NxWbLE+
# 6Dxv45y1+0PGPMM4Go7hYYpGmoPZlgormc1FO6a0TmsPJVqdtFt9L4pGIlDJC+dV
# rIVaKO6E91BYs0atluQLCPiNg5oPH90AbULGdlwbuVSQvYCTmxCwQfU2bGu8XBDH
# nOi5xNa5cF6l/SCfstjP/LC9a6I5d1+yMzwxahECT69kKYEEUZl2S1j1oYIYETCC
# GA0GCisGAQQBgjcDAwExghf9MIIX+QYJKoZIhvcNAQcCoIIX6jCCF+YCAQMxDzAN
# BglghkgBZQMEAgEFADCCAWIGCyqGSIb3DQEJEAEEoIIBUQSCAU0wggFJAgEBBgor
# BgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIFAxXUQ4zr/RtINHAJdb25IFeXRM
# WfLxvufgGKuRMv7pAgZpwnKumOUYEzIwMjYwMzMwMjIzNzM2LjE1OFowBIACAfSg
# geGkgd4wgdsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAj
# BgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5T
# aGllbGQgVFNTIEVTTjo3RDAwLTA1RTAtRDk0NzE1MDMGA1UEAxMsTWljcm9zb2Z0
# IFB1YmxpYyBSU0EgVGltZSBTdGFtcGluZyBBdXRob3JpdHmggg8hMIIHgjCCBWqg
# AwIBAgITMwAAAAXlzw//Zi7JhwAAAAAABTANBgkqhkiG9w0BAQwFADB3MQswCQYD
# VQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMUgwRgYDVQQD
# Ez9NaWNyb3NvZnQgSWRlbnRpdHkgVmVyaWZpY2F0aW9uIFJvb3QgQ2VydGlmaWNh
# dGUgQXV0aG9yaXR5IDIwMjAwHhcNMjAxMTE5MjAzMjMxWhcNMzUxMTE5MjA0MjMx
# WjBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0Eg
# MjAyMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJ5851Jj/eDFnwV9
# Y7UGIqMcHtfnlzPREwW9ZUZHd5HBXXBvf7KrQ5cMSqFSHGqg2/qJhYqOQxwuEQXG
# 8kB41wsDJP5d0zmLYKAY8Zxv3lYkuLDsfMuIEqvGYOPURAH+Ybl4SJEESnt0MbPE
# oKdNihwM5xGv0rGofJ1qOYSTNcc55EbBT7uq3wx3mXhtVmtcCEr5ZKTkKKE1CxZv
# NPWdGWJUPC6e4uRfWHIhZcgCsJ+sozf5EeH5KrlFnxpjKKTavwfFP6XaGZGWUG8T
# ZaiTogRoAlqcevbiqioUz1Yt4FRK53P6ovnUfANjIgM9JDdJ4e0qiDRm5sOTiEQt
# BLGd9Vhd1MadxoGcHrRCsS5rO9yhv2fjJHrmlQ0EIXmp4DhDBieKUGR+eZ4CNE3c
# tW4uvSDQVeSp9h1SaPV8UWEfyTxgGjOsRpeexIveR1MPTVf7gt8hY64XNPO6iyUG
# sEgt8c2PxF87E+CO7A28TpjNq5eLiiunhKbq0XbjkNoU5JhtYUrlmAbpxRjb9tSr
# eDdtACpm3rkpxp7AQndnI0Shu/fk1/rE3oWsDqMX3jjv40e8KN5YsJBnczyWB4Jy
# eeFMW3JBfdeAKhzohFe8U5w9WuvcP1E8cIxLoKSDzCCBOu0hWdjzKNu8Y5SwB1lt
# 5dQhABYyzR3dxEO/T1K/BVF3rV69AgMBAAGjggIbMIICFzAOBgNVHQ8BAf8EBAMC
# AYYwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFGtpKDo1L0hjQM972K9J6T7Z
# PdshMFQGA1UdIARNMEswSQYEVR0gADBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0l
# BAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDwYDVR0T
# AQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTIftJqhSobyhmYBAcnz1AQT2ioojCBhAYD
# VR0fBH0wezB5oHegdYZzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# cmwvTWljcm9zb2Z0JTIwSWRlbnRpdHklMjBWZXJpZmljYXRpb24lMjBSb290JTIw
# Q2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDIwLmNybDCBlAYIKwYBBQUHAQEE
# gYcwgYQwgYEGCCsGAQUFBzAChnVodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL2NlcnRzL01pY3Jvc29mdCUyMElkZW50aXR5JTIwVmVyaWZpY2F0aW9uJTIw
# Um9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAyMC5jcnQwDQYJKoZI
# hvcNAQEMBQADggIBAF+Idsd+bbVaFXXnTHho+k7h2ESZJRWluLE0Oa/pO+4ge/XE
# izXvhs0Y7+KVYyb4nHlugBesnFqBGEdC2IWmtKMyS1OWIviwpnK3aL5JedwzbeBF
# 7POyg6IGG/XhhJ3UqWeWTO+Czb1c2NP5zyEh89F72u9UIw+IfvM9lzDmc2O2END7
# MPnrcjWdQnrLn1Ntday7JSyrDvBdmgbNnCKNZPmhzoa8PccOiQljjTW6GePe5sGF
# uRHzdFt8y+bN2neF7Zu8hTO1I64XNGqst8S+w+RUdie8fXC1jKu3m9KGIqF4aldr
# YBamyh3g4nJPj/LR2CBaLyD+2BuGZCVmoNR/dSpRCxlot0i79dKOChmoONqbMI8m
# 04uLaEHAv4qwKHQ1vBzbV/nG89LDKbRSSvijmwJwxRxLLpMQ/u4xXxFfR4f/gksS
# kbJp7oqLwliDm/h+w0aJ/U5ccnYhYb7vPKNMN+SZDWycU5ODIRfyoGl59BsXR/Hp
# RGtiJquOYGmvA/pk5vC1lcnbeMrcWD/26ozePQ/TWfNXKBOmkFpvPE8CH+EeGGWz
# qTCjdAsno2jzTeNSxlx3glDGJgcdz5D/AAxw9Sdgq/+rY7jjgs7X6fqPTXPmaCAJ
# KVHAP19oEjJIBwD1LyHbaEgBxFCogYSOiUIr0Xqcr1nJfiWG2GwYe6ZoAF1bMIIH
# lzCCBX+gAwIBAgITMwAAAFXZ3WkmKPn44gAAAAAAVTANBgkqhkiG9w0BAQwFADBh
# MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIw
# MAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAy
# MDAeFw0yNTEwMjMyMDQ2NDlaFw0yNjEwMjIyMDQ2NDlaMIHbMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046N0QwMC0w
# NUUwLUQ5NDcxNTAzBgNVBAMTLE1pY3Jvc29mdCBQdWJsaWMgUlNBIFRpbWUgU3Rh
# bXBpbmcgQXV0aG9yaXR5MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# vbkfkh5ZSLP0MCUWafaw/KZoVZu9iQx8r5JwhZvdrUi86UjCCFQONjQanrIxGF9h
# RGIZLQZ50gHrLC+4fpUEJff5t04VwByWC2/bWOuk6NmaTh9JpPZDcGzNR95Qlryj
# fEjtl+gxj12zNPEdADPplVfzt8cYRWFBx/Fbfch08k6P9p7jX2q1jFPbUxWYJ+xO
# yGC1aKhDGY5b+8wL39v6qC0HFIx/v3y+bep+aEXooK8VoeWK+szfaFjXo8YTcvQ8
# UL4szu9HFTuZNv6vvoJ7Ju+o5aTj51sph+0+FXW38TlL/rDBd5ia79jskLtOeHbD
# jkbljilwzegcxv9i49F05ZrS/5ELZCCY1VaqO7EOLKVaxxdAO5oy1vb0Bx0ZRVX1
# mxFjYzay2EC051k6yGJHm58y1oe2IKRa/SM1+BTGse6vHNi5Q2d5ZnoR9AOAUDDw
# JIIqRI4rZz2MSinh11WrXTG9urF2uoyd5Ve+8hxes9ABeP2PYQKlXYTAxvdaeanD
# TQ/vwmnM+yTcWzrVm84Z38XVFw4G7p/ZNZ2nscvv6uru2AevXcyV1t8ha7iWmhhg
# TWBNBrViuDlc3iPvOz2SVPbPeqhyY/NXwNZCAgc2H5pOztu6MwQxDIjte3XM/FkK
# BxHofS2abNT/0HG+xZtFqUJDaxgbJa6lN1zh7spjuQ8CAwEAAaOCAcswggHHMB0G
# A1UdDgQWBBRWBF8QbdwIA/DIv6nJFsrB16xltjAfBgNVHSMEGDAWgBRraSg6NS9I
# Y0DPe9ivSek+2T3bITBsBgNVHR8EZTBjMGGgX6BdhltodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBQdWJsaWMlMjBSU0ElMjBU
# aW1lc3RhbXBpbmclMjBDQSUyMDIwMjAuY3JsMHkGCCsGAQUFBwEBBG0wazBpBggr
# BgEFBQcwAoZdaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9N
# aWNyb3NvZnQlMjBQdWJsaWMlMjBSU0ElMjBUaW1lc3RhbXBpbmclMjBDQSUyMDIw
# MjAuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYD
# VR0PAQH/BAQDAgeAMGYGA1UdIARfMF0wUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYB
# BQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBv
# c2l0b3J5Lmh0bTAIBgZngQwBBAIwDQYJKoZIhvcNAQEMBQADggIBAFIe4ZJUe9qU
# KcWeWypchB58fXE/ZIWv2D5XP5/k/tB7LCN9BvmNSVKZ3VeclQM978wfEvuvdMQS
# Uv6Y20boIM8DK1K1IU9cP21MG0ExiHxaqjrikf2qbfrXIip4Ef3v2bNYKQxCxN3S
# czp1SX0H7uqK2L5OhfDEiXf15iou5hh+EPaaqp49czNQpJDOR/vfJghUc/qcslDP
# hoCZpZx8b2ODvywGQNXwqlbsmCS24uGmEkQ3UH5JUeN6c91yasVchS78riMrm6R9
# ZpAiO5pfNKMGU2MLm1A3pp098DcbFTAc95Hh6Qvkh//28F/Xe2bMFb6DL7Sw0ZO9
# 5v0gv0ZTyJfxS/LCxfraeEII9FSFOKAMEp1zNFSs2ue0GGjBt9yEEMUwvxq9ExFz
# 0aZzYm8ivJfffpIVDnX/+rVRTYcxIkQyFYslIhYlWF9SjCw5r49qakjMRNh8W9O7
# aaoolSVZleQZjGt0K8JzMlyp6hp2lbW6XqRx2cOHbbxJDxmENzohGUziI13lI2g2
# Bf5qibfC4bKNRpJo9lbE8HUbY0qJiE8u3SU8eDQaySPXOEhJjxRCQwwOvejYmBG5
# P7CckQNBSnnl12+FKRKgPoj0Mv+z5OMhj9z2MtpbnHLAkep0odQClEyyCG/uR5tK
# 5rW6mZH5Oq56UWS0NI6NV1JGS7Jri6jFMYIHQzCCBz8CAQEweDBhMQswCQYDVQQG
# EwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylN
# aWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMAITMwAAAFXZ
# 3WkmKPn44gAAAAAAVTANBglghkgBZQMEAgEFAKCCBJwwEQYLKoZIhvcNAQkQAg8x
# AgUAMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcN
# MjYwMzMwMjIzNzM2WjAvBgkqhkiG9w0BCQQxIgQgj0r4CtjAewPL0YbIfp5/EGbZ
# EXyyfNOrkV4BaCBvr5IwgbkGCyqGSIb3DQEJEAIvMYGpMIGmMIGjMIGgBCDYuTyX
# ZIZiu799/v4PaqsmeSzBxh0rqkYq7sYYavj+zTB8MGWkYzBhMQswCQYDVQQGEwJV
# UzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNy
# b3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMAITMwAAAFXZ3Wkm
# KPn44gAAAAAAVTCCA14GCyqGSIb3DQEJEAISMYIDTTCCA0mhggNFMIIDQTCCAikC
# AQEwggEJoYHhpIHeMIHbMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYD
# VQQLEx5uU2hpZWxkIFRTUyBFU046N0QwMC0wNUUwLUQ5NDcxNTAzBgNVBAMTLE1p
# Y3Jvc29mdCBQdWJsaWMgUlNBIFRpbWUgU3RhbXBpbmcgQXV0aG9yaXR5oiMKAQEw
# BwYFKw4DAhoDFQAdO1QBgmW/tuBZV5EGjhfsV4cN6qBnMGWkYzBhMQswCQYDVQQG
# EwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylN
# aWNyb3NvZnQgUHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMDANBgkqhkiG
# 9w0BAQsFAAIFAO102h0wIhgPMjAyNjAzMzAxMTE2NDVaGA8yMDI2MDMzMTExMTY0
# NVowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA7XTaHQIBADAHAgEAAgIIIzAHAgEA
# AgISvDAKAgUA7XYrnQIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBCwUAA4IBAQAK877s
# agl4GbNJbhHNZdXMFJLS6U8vywIt668EFo2xxl8FYVZ2sT+1OUL0UHZzSHbchC+D
# ciOmqJert7xuM7t10gbLULkjwx4GCrwWoLpLRMGQwO7d7OLFJcbM27VGDgpt9ySn
# oVNE506gPe05jlfoyhqL3f1EztzmVUDDa5QOkRxCZpEUbvq40aRKBr/B69HzEawO
# L0/uWGTC/oEv3s8vZLM/zM0sAeKWzedzF7Z4oDpBnoWOyjvk5F2XdkEo4CUba/G/
# sL5Fiml5M0xCcKPcDYD99txMBETKpp9j0811Ja08BgFVgMWAjli0k4wFqjk6r2Jb
# e4d6W2EWeLvfq0V8MA0GCSqGSIb3DQEBAQUABIICAJTC5jVw52FNFcGOm8Vjry6C
# hHiaIVEhT3A9kKFPJ8gfztJ7x6iICEinpWWLqffo0HDbrX8ERsVqES/90ERz+Vkf
# z3s/9Fu8+e7bAAZmUSB9aCTshd74J0aaDesaPtl/Y9O4wAWG2NYXUgLvnzLHADc+
# q3XZEkLCB3TzAhO3ooFrCd83MTURbbFv4uAg5A5katfDVlJWpGvJRja0Zubbk0Et
# MVCFsjFGRASMM/4n6WnjvR1lTZGS/LL3A4FzqIN87cbR5JG5mScjf6UBPyu1cLiy
# VYTHtmsg+AoxtovOIK5R16OJY0fqkDo2habhKUCWXi0ZRKfgtQ7FduAg4PwPQEyv
# zLiuNr2d5jeCJXDapg7cAWLuw1vMGjhNe1I2H0Niu297EORafxI0nJAHBBb9ZyXL
# +SxvXgKYOMwTAKaRHgIGDyiNAOGTcRPjud11UtFO+a9c+eZxi/CDZsz7rUaIZ/St
# G/g4yel15XuarZ8OziE+U47n/wKxVkkBQSCCWmhCQk4L3JyGpOmpgnH5mJlOXGcL
# bert6Wrmq6T5dITh6oqV79iuLFl2ly7rYyJU+IP/Idzz/6uDIR3KlrA9B3yvCdF3
# WdIOyQs9DHHFXUUSsLTG6HvCBdAgarLfHI7IxjwEBjmAD8UGjs6ZRvXMb0iGhZSR
# 5LJEgk6cbjhO1HdBEad+
# SIG # End signature block
