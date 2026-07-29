# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

$Script:Action1_OrganizationExportCsvColumns = @(
    'Id'
    'Name'
    'Description'
    'EntityType'
    'EnterpriseId'
    'Region'
    'ExportedAt'
)

$Script:Action1_OrganizationMigrationMapCsvColumns = @(
    'EntityType'
    'SourceId'
    'SourceName'
    'SourceRegion'
    'SourceEnterpriseId'
    'TargetRegion'
    'TargetEnterpriseId'
    'TargetId'
    'TargetName'
    'Status'
    'ImportedAt'
)
