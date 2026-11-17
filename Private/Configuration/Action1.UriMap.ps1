# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

# Route-builder parameters use PascalCase names, such as OrgId and ObjectId.
$Script:Action1_UriMap = @{
    # Configuration
    G_AdvancedSettings     = { param($OrgId) "/setting_templates/$OrgId" }
    G_Logs                 = { param($OrgId) "/logs/$OrgId" }
    G_Me                   = { "/Me" }

    # Enterprise
    G_Enterprise           = { "/enterprise" }
    U_Enterprise           = { "/enterprise" }

    # Organization
    G_Organization         = { param($OrgId) "/organizations/$OrgId" }
    G_Organizations        = { "/organizations" }
    N_Organization         = { "/organizations" }
    U_Organization         = { param($OrgId) "/organizations/$OrgId" }
    D_Organization         = { param($OrgId) "/organizations/$OrgId" }

    # User
    G_User                 = { param($UserId) "/users/$UserId" }
    G_UserRoles            = { param($UserId) "/users/$UserId/roles" }
    G_Users                = { "/users" }
    N_User                 = { "/users" }
    U_User                 = { param($UserId) "/users/$UserId" }
    D_User                 = { param($UserId) "/users/$UserId" }

    # Endpoint
    G_AgentDeployment      = { param($OrgId) "/endpoints/discovery/$OrgId" }
    G_Endpoints            = { param($OrgId) "/endpoints/managed/$OrgId" }
    G_Endpoint             = { param($OrgId, $ObjectId) "/endpoints/managed/$OrgId/$ObjectId" }
    U_Endpoint             = { param($OrgId, $ObjectId) "/endpoints/managed/$OrgId/$ObjectId" }
    D_Endpoint             = { param($OrgId, $ObjectId) "/endpoints/managed/$OrgId/$ObjectId" }

    # EndpointGroup
    G_EndpointGroup        = { param($OrgId, $ObjectId) "/endpoints/groups/$OrgId/$ObjectId" }
    G_EndpointGroups       = { param($OrgId) "/endpoints/groups/$OrgId" }
    N_EndpointGroup        = { param($OrgId) "/endpoints/groups/$OrgId" }
    U_EndpointGroup        = { param($OrgId, $ObjectId) "/endpoints/groups/$OrgId/$ObjectId" }
    D_EndpointGroup        = { param($OrgId, $ObjectId) "/endpoints/groups/$OrgId/$ObjectId" }
    G_EndpointGroupMembers = { param($OrgId, $ObjectId)"/endpoints/groups/$OrgId/$ObjectId/contents" }
    N_EndpointGroupMembers = { param($OrgId, $ObjectId) "/endpoints/groups/$OrgId/$ObjectId/contents" }
    U_EndpointGroupMembers = { param($OrgId, $ObjectId) "/endpoints/groups/$OrgId/$ObjectId/contents" }
    D_EndpointGroupMembers = { param($OrgId, $ObjectId) "/endpoints/groups/$OrgId/$ObjectId/contents" }

    # App
    G_Apps                 = { param($OrgId) "/apps/$OrgId/data" }
    G_EndpointApps         = { param($OrgId, $ObjectId) "/apps/$OrgId/data/$ObjectId" }
    R_InstalledSoftware    = { param($OrgId, $ObjectId) "/apps/$OrgId/requery/$ObjectId" }

    # Package
    G_Packages             = { "/packages/all" }
    G_PackageVersions      = { param($ObjectId) "/software-repository/all/$ObjectId`?fields=versions" }
    G_Scripts              = { "/scripts/all" }

    # Automation
    G_AutomationInstances  = {
        param($OrgId, $ObjectId)

        $uri = "/automations/instances/$OrgId"

        if (-not [string]::IsNullOrWhiteSpace([string]$ObjectId)) {
            $encodedEndpointId = [System.Uri]::EscapeDataString([string]$ObjectId)
            $uri += "?endpoint_id=$encodedEndpointId"
        }

        $uri
    }
    N_DeploySoftware       = { param($OrgId)  "/automations/instances/$OrgId" }
    G_AutomationInstance   = { param($OrgId, $ObjectId) "/automations/instances/$OrgId/$ObjectId" }
    N_AutomationInstance   = { param($OrgId) "/automations/instances/$OrgId" }
    G_AutomationInstanceEndpoints = {
        param($OrgId, $ObjectId)

        "/automations/instances/$OrgId/$ObjectId/endpoint-results"
    }
    G_AutomationInstanceEndpointDetails = {
        param($OrgId, $AutomationInstanceId, $EndpointId)

        "/automations/instances/$OrgId/$AutomationInstanceId/endpoint-results/$EndpointId/details"
    }
    G_AutomationSchedules  = { param($OrgId) "/automations/schedules/$OrgId" }
    N_AutomationSchedule   = { param($OrgId) "/automations/schedules/$OrgId" }
    G_Automations          = { param($OrgId) "/automations/schedules/$OrgId" }
    N_Automation           = { param($OrgId)  "/automations/schedules/$OrgId" }
    N_DeferredRemediation  = { param($OrgId)  "/automations/schedules/$OrgId" }
    U_Automation           = { param($OrgId, $ObjectId)  "/automations/schedules/$OrgId/$ObjectId" }
    G_AutomationActionTemplates = { "/automations/action-templates" }
    G_AutomationActionTemplate = { param($TemplateId) "/automations/action-templates/$TemplateId" }

    # Policy. Outdated. Endpoint /policies -> /automations. Policy -> AutomationInstance
    G_Policy               = { param($OrgId, $ObjectId) "/automations/instances/$OrgId/$ObjectId" }
    G_Policies             = { param($OrgId)  "/automations/instances/$OrgId" }
    G_PolicyResults        = { param($OrgId, $ObjectId) "/automations/instances/$OrgId/$ObjectId/endpoint_results" }
    N_Remediation          = { param($OrgId)  "/automations/instances/$OrgId" }

    # Report
    G_ReportData           = { param($OrgId, $ObjectId)"/reportdata/$OrgId/$ObjectId/data" }
    G_ReportExport         = { param($OrgId, $ObjectId)"/reportdata/$OrgId/$ObjectId/export" }
    G_Reports              = { "/reports/all" } 
    R_ReportData           = { param($OrgId, $ObjectId) "/reportdata/$OrgId/$ObjectId/requery" }

    # Update
    G_MissingUpdates       = { param($OrgId) "/updates/$OrgId" }
    R_InstalledUpdates     = { param($OrgId) "/updates/installed/$OrgId/requery" }

    # Vulnerability
    G_Vulnerabilities              = { param($OrgId) "/vulnerabilities/$OrgId" }
    G_Vulnerability                = { param($OrgId, $CVEId) "/vulnerabilities/$OrgId/$CVEId" }
    G_VulnerabilityEndpoints       = { param($OrgId, $CVEId) "/vulnerabilities/$OrgId/$CVEId/endpoints" }
    G_VulnerabilityRemediations    = { param($OrgId, $CVEId) "/vulnerabilities/$OrgId/$CVEId/remediations" }
    N_VulnerabilityRemediation     = { param($OrgId, $CVEId) "/vulnerabilities/$OrgId/$CVEId/remediations" }
    U_VulnerabilityRemediation     = { param($OrgId, $CVEId, $RemediationId) "/vulnerabilities/$OrgId/$CVEId/remediations/$RemediationId" }
    D_VulnerabilityRemediation     = { param($OrgId, $CVEId, $RemediationId) "/vulnerabilities/$OrgId/$CVEId/remediations/$RemediationId" }
}
