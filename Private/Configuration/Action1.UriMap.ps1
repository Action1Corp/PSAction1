# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

$Script:Action1_UriMap = @{
    # Configuration
    G_AdvancedSettings     = { param($Org_ID) "/setting_templates/$Org_ID" }
    G_Logs                 = { param($Org_ID) "/logs/$Org_ID" }
    G_Me                   = { "/Me" }

    # Enterprise
    G_Enterprise           = { "/enterprise" }
    U_Enterprise           = { "/enterprise" }

    # Organization
    G_Organization         = { param($Org_ID) "/organizations/$Org_ID" }
    G_Organizations        = { "/organizations" }
    N_Organization         = { "/organizations" }
    U_Organization         = { param($Org_ID) "/organizations/$Org_ID" }
    D_Organization         = { param($Org_ID) "/organizations/$Org_ID" }

    # Endpoint
    G_AgentDeployment      = { param($Org_ID) "/endpoints/discovery/$Org_ID" }
    G_Endpoints            = { param($Org_ID) "/endpoints/managed/$Org_ID" }
    G_Endpoint             = { param($Org_ID, $Object_ID) "/endpoints/managed/$Org_ID/$Object_ID" }
    U_Endpoint             = { param($Org_ID, $Object_ID) "/endpoints/managed/$Org_ID/$Object_ID" }
    D_Endpoint             = { param($Org_ID, $Object_ID) "/endpoints/managed/$Org_ID/$Object_ID" }

    # EndpointGroup
    G_EndpointGroupMembers = { param($Org_ID, $Object_ID)"/endpoints/groups/$Org_ID/$Object_ID/contents" }
    G_EndpointGroup        = { param($Org_ID, $Object_ID) "/endpoints/groups/$Org_ID/$Object_ID" }
    G_EndpointGroups       = { param($Org_ID) "/endpoints/groups/$Org_ID" }
    N_EndpointGroup        = { param($Org_ID) "/endpoints/groups/$Org_ID" }
    N_EndpointGroupMembers = { param($Org_ID, $Object_ID) "/endpoints/groups/$Org_ID/$Object_ID/contents" }
    U_EndpointGroup        = { param($Org_ID, $Object_ID) "/endpoints/groups/$Org_ID/$Object_ID" }
    U_EndpointGroupMembers = { param($Org_ID, $Object_ID) "/endpoints/groups/$Org_ID/$Object_ID/contents" }
    D_EndpointGroupMembers = { param($Org_ID, $Object_ID) "/endpoints/groups/$Org_ID/$Object_ID/contents" }

    # App
    G_Apps                 = { param($Org_ID) "/apps/$Org_ID/data" }
    G_EndpointApps         = { param($Org_ID, $Object_ID) "/apps/$Org_ID/data/$Object_ID" }
    R_InstalledSoftware    = { param($Org_ID, $Object_ID) "/apps/$Org_ID/requery/$Object_ID" }

    # Package
    G_Packages             = { "/packages/all" }
    G_PackageVersions      = { param($Object_ID) "/software-repository/all/$Object_ID`?fields=versions" }
    G_Scripts              = { "/scripts/all" }
    N_DeploySoftware       = { param($Org_ID)  "/policies/instances/$Org_ID" }

    # Automation
    G_AutomationInstances  = { param($Org_ID, $Object_ID) "/automations/instances/$Org_ID`?endpoint_id=$Object_ID" }
    G_Automations          = { param($Org_ID) "/policies/schedules/$Org_ID" }
    N_Automation           = { param($Org_ID)  "/policies/schedules/$Org_ID" }
    N_DeferredRemediation  = { param($Org_ID)  "/policies/schedules/$Org_ID" }
    U_Automation           = { param($Org_ID, $Object_ID)  "/policies/schedules/$Org_ID/$Object_ID" }

    # Policy
    G_Policy               = { param($Org_ID, $Object_ID) "/policies/instances/$Org_ID/$Object_ID" }
    G_Policies             = { param($Org_ID)  "/policies/instances/$Org_ID" }
    G_PolicyResults        = { param($Org_ID, $Object_ID) "/policies/instances/$Org_ID/$Object_ID/endpoint_results" }
    N_Remediation          = { param($Org_ID)  "/policies/instances/$Org_ID" }

    # Report
    G_ReportData           = { param($Org_ID, $Object_ID)"/reportdata/$Org_ID/$Object_ID/data" }
    G_ReportExport         = { param($Org_ID, $Object_ID)"/reportdata/$Org_ID/$Object_ID/export" }
    G_Reports              = { "/reports/all" } 
    R_ReportData           = { param($Org_ID, $Object_ID) "/reportdata/$Org_ID/$Object_ID/requery" }

    # Update
    G_MissingUpdates       = { param($Org_ID) "/updates/$Org_ID" }
    R_InstalledUpdates     = { param($Org_ID) "/updates/installed/$Org_ID/requery" }

    # Vulnerability
    G_Vulnerabilities              = { param($Org_ID) "/vulnerabilities/$Org_ID" }
    G_Vulnerability                = { param($Org_ID, $CVEId) "/vulnerabilities/$Org_ID/$CVEId" }
    G_VulnerabilityEndpoints       = { param($Org_ID, $CVEId) "/vulnerabilities/$Org_ID/$CVEId/endpoints" }
    G_VulnerabilityRemediations    = { param($Org_ID, $CVEId) "/vulnerabilities/$Org_ID/$CVEId/remediations" }
    N_VulnerabilityRemediation     = { param($Org_ID, $CVEId) "/vulnerabilities/$Org_ID/$CVEId/remediations" }
    U_VulnerabilityRemediation     = { param($Org_ID, $CVEId, $RemediationId) "/vulnerabilities/$Org_ID/$CVEId/remediations/$RemediationId" }
    D_VulnerabilityRemediation     = { param($Org_ID, $CVEId, $RemediationId) "/vulnerabilities/$Org_ID/$CVEId/remediations/$RemediationId" }
}
