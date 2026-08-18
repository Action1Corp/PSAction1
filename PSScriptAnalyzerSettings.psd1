# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

@{
    CustomRulePath = @(
        '.\tools\PSScriptAnalyzer\PSAction1.AnalyzerRules.psm1'
    )

    IncludeDefaultRules = $true

    Severity = @(
        'Error'
        'Warning'
    )

    ExcludeRules = @(
        # The repository keeps UTF-8 files without BOM.
        'PSUseBOMForUnicodeEncodedFile'

        # Public cmdlet names must remain stable after release.
        'PSUseSingularNouns'

        # This module intentionally uses manifest wildcards for these fields.
        'PSUseToExportFieldsInManifest'

        # Several Set-* commands change only module state and should stay simple.
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
