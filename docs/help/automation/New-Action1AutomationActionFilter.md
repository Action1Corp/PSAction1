---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# New-Action1AutomationActionFilter

## SYNOPSIS

Builds an automation action filter locally.

## SYNTAX

```powershell
New-Action1AutomationActionFilter -Name <String> -Values <String[]> -Operator <String> [<CommonParameters>]
```

## DESCRIPTION

Creates an object with `name`, `values`, and `operator` for an action's
`params.filters` array. No API request is made. Values remain an array even
when there is only one value. The operator is normalized to lowercase.

Separate update filters combine with AND; included values within one filter
combine with OR. The include/exclude operator controls whether matching values
are selected or excluded. Filter names and values are not restricted to a
hard-coded catalogue; API support depends on the action and API version.

## EXAMPLES

### Example 1: Select security updates

```powershell
$filter = New-Action1AutomationActionFilter -Name update_types `
    -Values 'Security Updates' -Operator include
```

Builds a filter with a singleton values array.

### Example 2: Exclude application updates

```powershell
$filter = New-Action1AutomationActionFilter -Name update_sources `
    -Values Applications -Operator exclude
```

Builds a filter that can be supplied inside the Parameters object of a deploy_update action.

## PARAMETERS

### -Name

The API filter key. Known captured keys are update_types, update_sources, and update_security_severities. Must be nonempty and non-whitespace.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Values

One or more nonempty, non-whitespace filter values. Null entries are rejected.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Operator

The filter operation. Accepted values: include, exclude.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe input to this command.

## OUTPUTS

### System.Management.Automation.PSCustomObject

Returns one PSCustomObject containing `name`, `values` as an array, and `operator`.

## NOTES

Captured deployment-filter examples are from API 3.0. API 4.0 deployment-filter
support has not been verified live. This command validates structure and does
not discover filter keys or validate values against the server.

## RELATED LINKS

[New-Action1AutomationAction](New-Action1AutomationAction.md)
[New-Action1AutomationDefinition](New-Action1AutomationDefinition.md)
