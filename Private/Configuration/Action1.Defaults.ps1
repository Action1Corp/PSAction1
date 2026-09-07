# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

# Basic params
$Script:Action1_429RetryBaseTimeoutSeconds = 2

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
