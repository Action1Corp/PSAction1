---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1AutomationActionTemplate

## SYNOPSIS

Gets one automation action template by ID from Action1.

## SYNTAX

```
Get-Action1AutomationActionTemplate [-TemplateId] <String> [<CommonParameters>]
```

## DESCRIPTION

Gets an automation action template from `/automations/action-templates/{templateId}`.
This route does not require a default organization.

The command calls the shared API request helper without pagination and returns
the response object without changing its properties.

## EXAMPLES

### Example 1: Get an automation action template by ID

```powershell
Get-Action1AutomationActionTemplate -TemplateId '11111111-1111-1111-1111-111111111111'
```

Gets the specified automation action template.

### Example 2: Display automation action template details

```powershell
Get-Action1AutomationActionTemplate '11111111-1111-1111-1111-111111111111' |
    Format-List
```

Passes the template ID positionally and displays all returned fields.

## PARAMETERS

### -TemplateId

Specifies the ID of the automation action template to retrieve. The value cannot
be null or empty.

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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe input to this command.

## OUTPUTS

### System.Object

Returns the automation action template object returned by Action1.

## NOTES

The command uses **Invoke-Action1ApiRequest** to send a single GET request.

## RELATED LINKS

[Get-Action1AutomationActionTemplates](Get-Action1AutomationActionTemplates.md)
