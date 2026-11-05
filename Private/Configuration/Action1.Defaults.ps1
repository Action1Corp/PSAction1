# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

# Basic params
$Script:Action1_429RetryBaseTimeoutSeconds = 2

# SHA256 hash validation
$Script:Action1_Sha256ValidationPattern = '^[a-fA-F0-9]{64}$'

# Bundled signing tool with download recovery for a missing executable.
$Script:Action1_SignToolPath = Join-Path $Script:ModuleRoot 'tools\Action1Sign'
$Script:Action1_SignToolFileName = 'action1sign.exe'
$Script:Action1_SignToolReleaseApiUrl =
    'https://api.github.com/repos/Action1Corp/Action1Sign/releases/latest'
$Script:Action1_SignToolAssetPattern = 'action1sign-*-windows-x86.zip'
$Script:Action1_SignToolSha256 = '2E0E41B12B3B4CC566FEFE67F0CBA91609D4C7D316369396115FB2578728BBA9'

# Pagination
$Script:Action1_PagedGetRequestDefaultLimit = 200
$Script:Action1_PagedGetRequestDefaultOffset = 0
$Script:Action1_ExportPageSize = 200

# Timestamp template
$Script:Action1_UtcTimestampTemplate = "yyyy-MM-dd'T'HH:mm:ss'Z'"
$Script:Action1_ApiTimestampTemplate = 'yyyy-MM-dd_HH-mm-ss'
$Script:Action1_ExportFileNameTimestampTemplate = "yyMMdd_HHmmss'Z'"

# CSV export file name template
$Script:Action1_VulnerabilitiesEndpointsExportFileNameTemplate =
    'Action1_{0}_VulnerabilitiesEndpoints_{1}.csv'

# Vulnerability
$Script:Action1_CVEIdValidationPattern = '^CVE-\d{4}-\d{4,}$'

# User
$Script:Action1_EmailValidationPattern = '^[^@\s]+@[^@\s]+\.[^@\s]+$'
$Script:Action1_TimezoneValidationPattern =
    '^[A-Za-z][A-Za-z0-9_+-]*/[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*$'

# Known user-create error returned after the user may already have been created.
$Script:Action1_UserCreateRecoveryErrorText = @(
    'Lead'
    'invalid ID field: undefined'
)
$Script:Action1_UserCreateRecoveryAttempts = 3
$Script:Action1_UserCreateRecoveryDelaySeconds = 1
$Script:Action1_UserAlreadyExistsErrorText = 'This user already exists in this enterprise.'
