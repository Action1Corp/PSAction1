---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1

## SYNOPSIS

Retrieves Action1 objects, reports, raw API responses, and configuration templates.

## SYNTAX

```
Get-Action1 [-Query] <String> [[-Id] <String>] [[-Limit] <Int32>] [[-URI] <String>] [[-For] <String>] [[-Clone] <String>] [<CommonParameters>]
```

## DESCRIPTION

The `Get-Action1` function retrieves Action1 objects and data from the Action1 API.
It can also return helper template objects used to create or modify Action1 resources with commands such as `New-Action1` and `Update-Action1`.

Depending on the value of the `Query` parameter, the command can retrieve Action1 resources such as endpoints, endpoint groups, automations, policies, reports, packages, vulnerabilities, and the current user information.

When `Query` is set to `RawURI`, the command performs a direct GET request against the API path specified by the `URI` parameter.

When `Query` is set to `Settings`, the command returns a template object for the resource type specified by the `For` parameter.
For supported resource types, the returned template can include helper script methods for modifying the object before sending it back to the API.

For long list queries, pagination is handled automatically.
If the `Limit` parameter is not specified, the function uses a page size of 200.

Some returned objects include helper methods for convenience.
Policy result objects include a `GetDetails()` method.
Endpoint-related objects include a `GetCustomAttribute()` method.

The default Action1 organization should be configured before running organization-scoped queries.
Use `Set-Action1DefaultOrg` to configure the default organization.

## EXAMPLES

### Example 1

```powershell
PS C:\> Get-Action1 -Query Endpoints
```

Returns all endpoints belonging to the current default Action1 organization.

### Example 2

```powershell
PS C:\> Get-Action1 -Query Endpoint -Id "12345"
```

Retrieves a specific Action1 endpoint by ID.

### Example 3

```powershell
PS C:\> Get-Action1 -Query RawURI -URI "/v1/packages"
```

Performs a direct Action1 API GET request using the specified API path.

### Example 4

```powershell
PS C:\> Get-Action1 -Query Settings -For EndpointGroup
```

Returns a new Action1 endpoint group template object that can be customized and used with `New-Action1`.

### Example 5

```powershell
PS C:\> Get-Action1 -Query Settings -For EndpointGroup -Clone "group-id"
```

Creates a new Action1 endpoint group template cloned from an existing endpoint group.

### Example 6

```powershell
PS C:\> Get-Action1 -Query PolicyResults | ForEach-Object { $_.GetDetails() }
```

Retrieves Action1 policy results and then fetches the detailed records for each result.

### Example 7

```powershell
PS C:\> Get-Action1 -Query Endpoints -Limit 50
```

Retrieves Action1 endpoints with an API page size of 50 objects.

### Example 8

```powershell
PS C:\> Get-Action1 -Query Settings -For DeploySoftware
```

Returns a deployment template object used to prepare a software deployment request.

## PARAMETERS

### -Query

Specifies the type of Action1 object, data set, raw API request, or template to retrieve.

Accepted values:

- AutomationInstances
- Automations
- AdvancedSettings
- Apps
- CustomAttribute
- EndpointGroupMembers
- EndpointGroups
- Me
- Endpoint
- EndpointApps
- Endpoints
- Logs
- MissingUpdates
- Organizations
- Packages
- PackageVersions
- Policy
- Policies
- PolicyResults
- ReportData
- ReportExport
- Reports
- Scripts
- AgentDeployment
- Vulnerabilities
- RawURI
- Settings

When this parameter is set to `RawURI`, the `URI` parameter must also be specified.
When this parameter is set to `Settings`, the `For` parameter must also be specified.

```yaml
Type: String
Parameter Sets: (All)
Aliases:
Accepted values: AutomationInstances, Automations, AdvancedSettings, Apps, CustomAttribute, EndpointGroupMembers, EndpointGroups, Me, Endpoint, EndpointApps, Endpoints, Logs, MissingUpdates, Organizations, Packages, PackageVersions, Policy, Policies, PolicyResults, ReportData, ReportExport, Reports, Scripts, AgentDeployment, Vulnerabilities, RawURI, Settings

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Id

Specifies the identifier of the Action1 object to retrieve.

Use this parameter with queries that retrieve a specific resource instance rather than a list.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Limit

Specifies the maximum number of records requested per paged API call.

This parameter maps to the API page-size limit used by paged requests.
If this parameter is not specified or is set to `0`, the function uses a page size of 200.
The value must be greater than or equal to 0.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### -URI

Specifies a literal API path for a direct GET request.

This parameter is required when `Query` is set to `RawURI`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -For

Specifies the Action1 resource type when retrieving template objects.

This parameter is used when `Query` is set to `Settings`.

Accepted values:

- Automation
- Endpoint
- EndpointGroup
- Organization
- GroupAddEndpoint
- GroupDeleteEndpoint
- GroupFilter
- Remediation
- DeferredRemediation
- DeploySoftware

```yaml
Type: String
Parameter Sets: (All)
Aliases:
Accepted values: Automation, Endpoint, EndpointGroup, Organization, GroupAddEndpoint, GroupDeleteEndpoint, GroupFilter, Remediation, DeferredRemediation, DeploySoftware

Required: False
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Clone

Specifies the ID of an existing Action1 object to clone when generating a template.

This parameter is only used when `Query` is set to `Settings`.
The function supports cloning for selected template types, including endpoint groups and automations.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe objects to this command.

## OUTPUTS

### System.Object

Returns objects retrieved from the Action1 API or template objects created by the function.
The returned object type depends on the value of the `Query` parameter.
Some returned objects may include helper script methods for additional operations.

## NOTES

Valid API credentials must be configured before using this command.
Use `Set-Action1Credentials` to configure API credentials.

The default Action1 organization should be configured with `Set-Action1DefaultOrg` before running organization-scoped queries.

Pagination is automatically processed for long list queries.
Some queries return raw API responses, while others return processed objects with helper methods.

## RELATED LINKS

[New-Action1](New-Action1.md)

[Update-Action1](Update-Action1.md)

[Set-Action1Credentials](Set-Action1Credentials.md)

[Set-Action1DefaultOrg](Set-Action1DefaultOrg.md)
