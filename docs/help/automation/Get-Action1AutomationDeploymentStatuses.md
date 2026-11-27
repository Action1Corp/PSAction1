---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1AutomationDeploymentStatuses

## SYNOPSIS

Gets deployment statuses for an automation schedule in the current Action1 organization.

## SYNTAX

### AllDeploymentStatuses (Default)

```
Get-Action1AutomationDeploymentStatuses [-AutomationInstanceId] <String> [-Limit <Int32>]
 [<CommonParameters>]
```

### AsPage

```
Get-Action1AutomationDeploymentStatuses [-AutomationInstanceId] <String> [-AsPages]
 [-Limit <Int32>] [<CommonParameters>]
```

## DESCRIPTION

Gets deployment statuses from
`/automations/schedules/{orgId}/{automationId}/deployment-statuses` by using the
module default organization configured by **Set-Action1DefaultOrg**.

By default, the command retrieves all API pages and returns individual deployment
status objects from each response's `items` array without changing their properties.

Use **AsPages** to return one envelope object per API page. Use **Limit** to
control how many deployment statuses are requested per API page. The value must
be from 1 through 200. The default value is 200.

## EXAMPLES

### Example 1: Get deployment statuses for an automation schedule

```powershell
Get-Action1AutomationDeploymentStatuses -AutomationInstanceId '11111111-1111-1111-1111-111111111111'
```

Gets deployment statuses for the specified automation schedule in the current organization.

### Example 2: Display deployment status details

```powershell
Get-Action1AutomationDeploymentStatuses '11111111-1111-1111-1111-111111111111' |
    Format-List
```

Passes the automation schedule ID positionally and displays the returned fields.

### Example 3: Get deployment statuses as pages

```powershell
Get-Action1AutomationDeploymentStatuses '11111111-1111-1111-1111-111111111111' -AsPages -Limit 50
```

Retrieves all deployment status pages, requesting up to 50 records per API page.

## PARAMETERS

### -AutomationInstanceId

Specifies the ID of the automation schedule whose deployment statuses are requested.
The value cannot be null or empty. This parameter supplies the `{automationId}`
path segment.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AsPages

Returns page envelope objects instead of individual deployment status objects.
Each page object contains `Items`, `PageNumber`, `From`, `Limit`,
`TotalItems`, and `NextPage`.

This switch changes only the output format; the command still retrieves all
available pages. Without **Limit**, it requests 200 items per page. **Limit**
controls the requested page size, not the total number of returned items.

**AsPage** is available as an alias.

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

### -Limit

Specifies how many deployment statuses to request from Action1 per API page.
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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe input to this command.

## OUTPUTS

### System.Object

Returns deployment status objects from Action1. An empty `items` array produces
no deployment status objects.

When **AsPages** is used, each page object contains `Items`, `PageNumber`,
`From`, `Limit`, `TotalItems`, and `NextPage`. The `Items` property contains
the deployment status objects returned for that API page and can be empty.

## NOTES

Requires the default Action1 organization to be configured with
**Set-Action1DefaultOrg**.

The command uses **Invoke-Action1PagedGetRequest** to retrieve all result pages.

## RELATED LINKS

[Get-Action1AutomationSchedule](Get-Action1AutomationSchedule.md)
[Get-Action1AutomationSchedules](Get-Action1AutomationSchedules.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
