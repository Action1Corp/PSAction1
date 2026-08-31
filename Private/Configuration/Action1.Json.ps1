# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

# JSON serialization
$Script:Action1_JsonObjectConversionDepth = 10

# JSON export/import envelope
$Script:Action1_DefaultJsonHeader = [ordered]@{
    schema        = $null
    datetime      = $null
    region        = $null
    enterprise_id = $null
    type          = $null
    items         = $null
}

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

# JSON schema for export/import files
$Script:Action1_OrganizationJsonSchema = 'PSAction1.Organization.v1'
$Script:Action1_MappingJsonSchema = 'PSAction1.Mapping.v1'
$Script:Action1_UserJsonSchema = 'PSAction1.User.v1'
$Script:Action1_RoleJsonSchema = 'PSAction1.Role.v1'
$Script:Action1_EndpointJsonSchema = 'PSAction1.Endpoint.v1'
$Script:Action1_EndpointGroupJsonSchema = 'PSAction1.EndpointGroup.v1'
