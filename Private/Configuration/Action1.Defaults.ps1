# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

# Basic params
$Script:Action1_429RetryBaseTimeoutSeconds = 2
$Script:Action1_JsonObjectConversionDepth = 10

# Pagination
$Script:Action1_PagedGetRequestDefaultLimit = 200
$Script:Action1_PagedGetRequestDefaultOffset = 0
$Script:Action1_ExportPageSize = 200

# Timestamp template
$Script:Action1_UtcTimestampTemplate = "yyyy-MM-dd'T'HH:mm:ss'Z'"
$Script:Action1_ApiTimestampTemplate = 'yyyy-MM-dd_HH-mm-ss'
$Script:Action1_ExportFileNameTimestampTemplate = "yyMMdd_HHmmss'Z'"

# JSON export file name template
$Script:Action1_OrgExportFileNameTemplate = 'Action1_Organizations_{0}.json'
$Script:Action1_UsersExportFileNameTemplate = 'Action1_Users_{0}.json'
$Script:Action1_UserRolesExportFileNameTemplate =
    'Action1_UserRoles_{0}_{1}.json'
$Script:Action1_MigrationMappingFileNameTemplate =
    'Action1_MigrationMapping_{0}_{1}.json'
$Script:Action1_EndpointsExportFileNameTemplate =
    'Action1_{0}_Endpoints_{1}.json'
$Script:Action1_EndpointGroupsExportFileNameTemplate =
    'Action1_{0}_EndpointGroups_{1}.json'
$Script:Action1_EndpointGroupMembersExportFileNameTemplate =
    'Action1_{0}_EndpointGroupMembers_{1}_{2}.json'
$Script:Action1_VulnerabilitiesEndpointsExportFileNameTemplate =
    'Action1_{0}_VulnerabilitiesEndpoints_{1}.csv'

# JSON schema for export/import files    
$Script:Action1_OrganizationJsonSchema = 'PSAction1.Organization.v1'
$Script:Action1_MappingJsonSchema = 'PSAction1.Mapping.v1'
$Script:Action1_UserJsonSchema = 'PSAction1.User.v1'
$Script:Action1_RoleJsonSchema = 'PSAction1.Role.v1'
$Script:Action1_EndpointJsonSchema = 'PSAction1.Endpoint.v1'
$Script:Action1_EndpointGroupJsonSchema = 'PSAction1.EndpointGroup.v1'

# Vulnerability
$Script:Action1_CVEIdValidationPattern = '^CVE-\d{4}-\d{4,}$'
