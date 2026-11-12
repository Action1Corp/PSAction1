---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1AutomationInstanceEndpoints

## SYNOPSIS

Gets endpoint results for an automation instance in the current Action1 organization.

## SYNTAX

### AllEndpoints (Default)

```
Get-Action1AutomationInstanceEndpoints [-AutomationInstanceId] <String> [-Limit <Int32>]
 [<CommonParameters>]
```

### AsPage

```
Get-Action1AutomationInstanceEndpoints [-AutomationInstanceId] <String> [-AsPages]
 [-Limit <Int32>] [<CommonParameters>]
```

## DESCRIPTION

Gets endpoint results from
`/automations/instances/{orgId}/{automationInstanceId}/endpoint-results` by using
the module default organization configured by **Set-Action1DefaultOrg**.

By default, the command retrieves all API pages and returns individual endpoint
result objects to the pipeline without changing their properties.

Use **AsPages** to return one envelope object per API page. Use **Limit** to
control how many endpoint results are requested per API page. The value must be
from 1 through 200. The default value is 200.

## EXAMPLES

### Example 1: Get all endpoint results for an automation instance

```powershell
Get-Action1AutomationInstanceEndpoints -AutomationInstanceId '11111111-1111-1111-1111-111111111111'
```

Gets all endpoint results for the specified automation instance in the current
organization.

### Example 2: Use a smaller API page size

```powershell
Get-Action1AutomationInstanceEndpoints '11111111-1111-1111-1111-111111111111' -Limit 50
```

Passes the automation instance ID positionally and retrieves all endpoint
results, requesting up to 50 records per API page.

### Example 3: Get endpoint results as pages

```powershell
Get-Action1AutomationInstanceEndpoints `
    -AutomationInstanceId '11111111-1111-1111-1111-111111111111' `
    -AsPages `
    -Limit 50
```

Gets page envelope objects for the specified automation instance.

## PARAMETERS

### -AutomationInstanceId

Specifies the ID of the automation instance whose endpoint results are retrieved.
The value cannot be null or empty.

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

Returns page envelope objects instead of individual endpoint result objects.
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

### -Limit

Specifies how many endpoint results to request from Action1 per API page.
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

Returns endpoint result objects from Action1.

When **AsPages** is used, each page object contains `Items`, `PageNumber`,
`From`, `Limit`, `TotalItems`, and `NextPage`. The `Items` property contains
the endpoint results returned for that API page.

## NOTES

Requires the default Action1 organization to be configured with
**Set-Action1DefaultOrg**.

The command uses **Invoke-Action1PagedGetRequest** to retrieve results from
the Action1 API.

## RELATED LINKS

[Get-Action1AutomationInstance](Get-Action1AutomationInstance.md)
[Get-Action1AutomationInstances](Get-Action1AutomationInstances.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
