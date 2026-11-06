---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1AutomationActionTemplates

## SYNOPSIS

Gets automation action templates from Action1.

## SYNTAX

### AllAutomationActionTemplates (Default)

```
Get-Action1AutomationActionTemplates [-Limit <Int32>] [<CommonParameters>]
```

### AsPage

```
Get-Action1AutomationActionTemplates [-AsPage] [-Limit <Int32>] [<CommonParameters>]
```

## DESCRIPTION

Gets automation action template records from `/automations/action-templates`.
This route does not require a default organization.

By default, the command retrieves all API pages and returns individual
automation action template objects to the pipeline without changing their
properties.

Use **AsPage** to return one envelope object per API page for callers that need
to process automation action templates page by page.

Use **Limit** to control how many automation action templates are requested per
API page. The value must be from 1 through 200. The default value is 200.

## EXAMPLES

### Example 1: Get all automation action templates

```powershell
Get-Action1AutomationActionTemplates
```

Gets all automation action templates.

### Example 2: Use a smaller API page size

```powershell
Get-Action1AutomationActionTemplates -Limit 50
```

Gets all automation action templates, requesting up to 50 records per API page.

### Example 3: Get automation action template pages

```powershell
Get-Action1AutomationActionTemplates -AsPage -Limit 50
```

Gets automation action templates as page envelope objects, requesting up to 50
records per API page.

## PARAMETERS

### -AsPage

Returns page envelope objects instead of individual automation action template
objects. Each page object contains `Items`, `PageNumber`, `From`, `Limit`,
`TotalItems`, and `NextPage`.

```yaml
Type: SwitchParameter
Parameter Sets: AsPage
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Limit

Specifies how many automation action templates to request from Action1 per API
page. This controls the page size rather than the total number of returned
records.

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

Returns automation action template objects from Action1.

When **AsPage** is used, each page object contains `Items`, `PageNumber`,
`From`, `Limit`, `TotalItems`, and `NextPage`. The `Items` property contains
the automation action template objects returned for that API page.

## NOTES

The command uses the shared paged GET request helper to retrieve results from
the Action1 API.

## RELATED LINKS

[Get-Action1AutomationActionTemplate](Get-Action1AutomationActionTemplate.md)
[Get-Action1AutomationInstances](Get-Action1AutomationInstances.md)
[Get-Action1AutomationSchedules](Get-Action1AutomationSchedules.md)
