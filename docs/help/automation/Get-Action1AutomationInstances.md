---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1AutomationInstances

## SYNOPSIS

Gets automation instances for the current Action1 organization.

## SYNTAX

### AllAutomationInstances (Default)

```
Get-Action1AutomationInstances [-Limit <Int32>] [-EndpointId <String>] [-NotCompleted]
 [<CommonParameters>]
```

### AsPage

```
Get-Action1AutomationInstances [-AsPages] [-Limit <Int32>] [-EndpointId <String>] [-NotCompleted]
 [<CommonParameters>]
```

## DESCRIPTION

Gets automation instance records from `/automations/instances/{orgId}` by using
the module default organization configured by **Set-Action1DefaultOrg**.

By default, the command explicitly sends `completed=yes` to retrieve completed
automation instances. The API treats an omitted `completed` query parameter the
same as `completed=yes`.

Use **NotCompleted** to send `completed=no` and retrieve only automation
instances that have not completed. Omitting the switch or specifying
`-NotCompleted:$false` sends `completed=yes`. This switch selects between
completed and uncompleted instances; neither setting requests both categories.
It can be combined with **EndpointId**, **AsPages**, and **Limit**.

Use **EndpointId** to filter automation instances for a specific endpoint. The
command adds `endpoint_id={EndpointId}` to the request query string. Omit
**EndpointId** to retrieve automation instances without an endpoint filter.

The command retrieves all matching API pages and returns individual
automation instance objects to the pipeline without changing their properties.

Use **AsPages** to return one envelope object per API page for callers that need
to process automation instances page by page.

Use **Limit** to control how many automation instances are requested per API
page. The value must be from 1 through 200. The default value is 200.

## EXAMPLES

### Example 1: Get completed automation instances

```powershell
Get-Action1AutomationInstances
```

Gets all completed automation instances in the current organization by sending
`completed=yes`.

### Example 2: Use a smaller API page size

```powershell
Get-Action1AutomationInstances -Limit 50
```

Gets all completed automation instances, requesting up to 50 records per API page.

### Example 3: Get automation instance pages

```powershell
Get-Action1AutomationInstances -AsPages -Limit 50
```

Gets completed automation instances as page envelope objects, requesting up to
50 records per API page.

### Example 4: Get automation instances for an endpoint

```powershell
Get-Action1AutomationInstances -EndpointId '11111111-1111-1111-1111-111111111111'
```

Gets all completed automation instances for the specified endpoint in the current
organization.

### Example 5: Get pages for an endpoint

```powershell
Get-Action1AutomationInstances `
    -EndpointId '11111111-1111-1111-1111-111111111111' `
    -AsPages `
    -Limit 50
```

Gets page envelope objects of completed instances for the specified endpoint,
requesting up to 50 automation instances per API page.

### Example 6: Get uncompleted automation instances

```powershell
Get-Action1AutomationInstances -NotCompleted
```

Gets only automation instances that have not completed in the current
organization by sending `completed=no`.

## PARAMETERS

### -AsPages

Returns page envelope objects instead of individual automation instance objects.
Each page object contains `Items`, `PageNumber`, `From`, `Limit`,
`TotalItems`, and `NextPage`.

This switch changes only the output format; the command still retrieves all
available pages. Without **Limit**, it requests 200 items per page. **Limit**
controls the requested page size, not the total number of returned items.

**AsPage** remains available as an alias.

```yaml
Type: SwitchParameter
Parameter Sets: AsPage
Aliases: AsPage

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -EndpointId

Filters automation instances by endpoint ID. The value must be a non-empty,
valid GUID, using the same validation as **Get-Action1Endpoint**.

Omit this parameter to retrieve automation instances for the current
organization without an endpoint filter. Explicit null, empty, or malformed
values are rejected.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Limit

Specifies how many automation instances to request from Action1 per API page.
This controls the page size rather than the total number of returned records.

The value must be from 1 through 200. The default value is 200.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 200
Accept pipeline input: False
Accept wildcard characters: False
```

### -NotCompleted

Returns only automation instances that have not completed by sending
`completed=no`.

The switch is off by default. When omitted or explicitly set to `$false`, the
command sends `completed=yes` and retrieves completed instances. It does not
request both categories together.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe input to this command.

## OUTPUTS

### System.Object

Returns automation instance objects from Action1.

When **AsPages** is used, each page object contains `Items`, `PageNumber`,
`From`, `Limit`, `TotalItems`, and `NextPage`. The `Items` property contains
the automation instance objects returned for that API page.

## NOTES

Requires the default Action1 organization to be configured with
**Set-Action1DefaultOrg**.

The command uses the shared paged GET request helper to retrieve results from
the Action1 API.

## RELATED LINKS

[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
[Get-Action1Endpoint](../endpoint/Get-Action1Endpoint.md)
