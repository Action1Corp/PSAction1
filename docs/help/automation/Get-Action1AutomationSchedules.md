---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1AutomationSchedules

## SYNOPSIS

Gets automation schedules for the current Action1 organization.

## SYNTAX

### AllAutomationSchedules (Default)

```
Get-Action1AutomationSchedules [-Limit <Int32>] [<CommonParameters>]
```

### AsPage

```
Get-Action1AutomationSchedules [-AsPages] [-Limit <Int32>] [<CommonParameters>]
```

## DESCRIPTION

Gets automation schedule records from `/automations/schedules/{orgId}` by using
the module default organization configured by **Set-Action1DefaultOrg**.

By default, the command retrieves all API pages and returns individual
automation schedule objects to the pipeline without changing their properties.

Use **AsPages** to return one envelope object per API page for callers that need
to process automation schedules page by page.

Use **Limit** to control how many automation schedules are requested per API
page. The value must be from 1 through 200. The default value is 200.

## EXAMPLES

### Example 1: Get all automation schedules

```powershell
Get-Action1AutomationSchedules
```

Gets all automation schedules in the current organization.

### Example 2: Use a smaller API page size

```powershell
Get-Action1AutomationSchedules -Limit 50
```

Gets all automation schedules, requesting up to 50 records per API page.

### Example 3: Get automation schedule pages

```powershell
Get-Action1AutomationSchedules -AsPages -Limit 50
```

Gets automation schedules as page envelope objects, requesting up to 50 records
per API page.

## PARAMETERS

### -AsPages

Returns page envelope objects instead of individual automation schedule objects.
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

Specifies how many automation schedules to request from Action1 per API page.
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

Returns automation schedule objects from Action1.

When **AsPages** is used, each page object contains `Items`, `PageNumber`,
`From`, `Limit`, `TotalItems`, and `NextPage`. The `Items` property contains
the automation schedule objects returned for that API page.

## NOTES

Requires the default Action1 organization to be configured with
**Set-Action1DefaultOrg**.

The command uses the shared paged GET request helper to retrieve results from
the Action1 API.

## RELATED LINKS

[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
[Get-Action1AutomationInstances](Get-Action1AutomationInstances.md)
