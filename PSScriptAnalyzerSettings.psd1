@{
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
