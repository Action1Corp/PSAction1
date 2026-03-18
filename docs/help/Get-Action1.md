---

external help file: PSAction1-help.xml

Module Name: PSAction1

online version:

schema: 2.0.0

---

# Get-Action1



## SYNOPSIS



Retrieves Action1 objects, reports, and templates.



## SYNTAX



```powershell

Get-Action1 [-Query] <String> [[-Id] <String>] [[-Limit] <Int32>] [[-URI] <String>] [[-For] <String>]

 [[-Clone] <String>] [<CommonParameters>]

```



## DESCRIPTION



`Get-Action1` retrieves Action1 objects and data from the API, as well as helper templates used for creating or modifying resources.



Depending on the `-Query` value, the command can:



- Retrieve Action1 objects such as endpoints, policies, reports, packages, and automations.

- Retrieve raw API responses.

- Generate configuration templates used with other module commands such as `New-Action1` or `Update-Action1`.



When `-Query Settings` is used, the function returns template objects for different Action1 resource types (for example, EndpointGroup, Automation, Remediation, DeploySoftware). These templates may include helper script methods that simplify modifying the object before sending it back to the API.



Pagination is handled automatically for long list queries.



Some returned Action1 objects include helper methods for convenience:



- **PolicyResults** objects include a `GetDetails()` method.

- **Endpoint**-related objects include a `GetCustomAttribute()` method.



The default Action1 organization is expected to be set in advance by `Set-Action1DefaultOrg`



## EXAMPLES



### Example 1



```powershell

PS C:\> Get-Action1 -Query Endpoints

```



Returns all endpoints belonging to the current Action1 organization.



### Example 2



```powershell

PS C:\> Get-Action1 -Query Endpoint -Id "12345"

```



Retrieves a specific Action1 endpoint by ID.



### Example 3



```powershell

PS C:\> Get-Action1 -Query RawURI -URI "/v1/packages"

```



Executes a direct Action1 API GET call using the specified URI.



### Example 4



```powershell

PS C:\> Get-Action1  -Query Settings -For EndpointGroup

```



Returns a new Action1 Endpoint Group template object that can be customized and used with `New-Action1` command.



### Example 5



```powershell

PS C:\> Get-Action1  -Query Settings -For EndpointGroup -Clone "group-id"

```



Creates a new Action1 Endpoint Group template cloned from an existing group with Id "group-id"



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



## PARAMETERS




### -Query



Specifies the type of Action1 object or dataset to retrieve.



Accepted values:



 - AutomationInstances

 - Automations

 - AdvancedSettings

 - Apps

 - CutomAttribute

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

 - AgentDepoyment

 - Vulnerabilities

 - RawURI

 - Settings



```yaml

Type: String

Parameter Sets: (All)

Aliases:

Accepted values: AutomationInstances, Automations, AdvancedSettings, Apps, CutomAttribute, EndpointGroupMembers, EndpointGroups, Me, Endpoint, EndpointApps, Endpoints, Logs, MissingUpdates, Organizations, Packages, PackageVersions, Policy, Policies, PolicyResults, ReportData, ReportExport, Reports, Scripts, AgentDepoyment, Vulnerabilities, RawURI, Settings



Required: True

Position: 0

Default value: None

Accept pipeline input: False

Accept wildcard characters: False

```



### -Id



Specifies the identifier of the Action1 object to retrieve.



Used for queries that return a specific Action1 resource instance.



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



### -URI



Specifies a literal API path.



Required when `-Query RawURI` is used.



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



Specifies the Action1 resource type when retrieving Action1 template objects using `-Query Settings`.



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



Specifies the ID of an existing Action1 object to clone when generating templates.



This parameter is only valid when `-Query Settings` is used.



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



### -Limit



Specifies the maximum number of records requested per API call.



This parameter maps to the API limit query argument and can be used to control page size when retrieving large datasets.



```yaml

Type: Int32

Parameter Sets: (All)

Aliases:



Required: False

Position: 2

Default value: None

Accept pipeline input: False

Accept wildcard characters: False

```



### CommonParameters



This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).



## INPUTS



### None. You cannot pipe objects to this command.



## OUTPUTS



### System.Object. Returns objects retrieved from the API.



The returned type depends on the value of `-Query` parameter. Some objects may include helper script methods for additional operations.



## NOTES



Requires valid API credentials set with `Set-Action1Credentials`



The default Action1 organization is expected to be set in advance via `Set-Action1DefaultOrg`



Pagination is automatically processed for long list queries.



Some queries return raw API responses while others return processed objects with helper methods.



## RELATED LINKS



[New-Action1](New-Action1.md)



[Update-Action1](Update-Action1.md)



[Set-Action1Credentials](Set-Action1Credentials.md)



[Set-Action1DefaultOrg](Set-Action1DefaultOrg.md)
