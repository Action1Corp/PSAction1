---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# New-Action1AutomationAction

## SYNOPSIS

Builds an automation action locally from a template and parameter object.

## SYNTAX

```powershell
New-Action1AutomationAction -Name <String> -TemplateId <String> -Parameters <Object> [-ActionId <String>] [<CommonParameters>]
```

## DESCRIPTION

Creates one action containing `name`, `template_id`, `params`, and `id`.
The action can be reused with API 3.0 or API 4.0 definition builders.
No API request is made. Parameter properties populate the local action template
directly. Nested parameter objects are reused, so later edits to those objects
can affect the caller's original objects.

Local JSON templates cover run_script, deploy_update, and deploy_package.
The run_script template supplies an empty run_script_params array unless
overridden. No reboot, update approval, target, or deployment scope is selected
automatically. Unknown template IDs are accepted with the caller's parameter
object. Server-specific required parameters are the caller's responsibility.

Supplied filters are structurally validated. Additional action parameters are
preserved, including properties not present in the local templates.

## EXAMPLES

### Example 1: Build a script-library action

```powershell
$action = New-Action1AutomationAction -Name 'Maintenance script' `
    -TemplateId run_script -Parameters @{
        run_script_id = 'maintenance_script_id'
        run_script_params = @()
    }
```

Builds a script action with a generated ID.

### Example 2: Build an update deployment action

```powershell
$filter = New-Action1AutomationActionFilter -Name update_types `
    -Values 'Security Updates' -Operator include
$action = New-Action1AutomationAction -Name 'Security updates' `
    -TemplateId deploy_update -Parameters @{
        scope = 'MatchingFilters'
        filters = @($filter)
        reboot_options = @{ auto_reboot = 'no' }
    }
```

Builds an action with an explicit filter array and explicit reboot preference. Approval parameters can be supplied using the API contract.

### Example 3: Preserve an action ID

```powershell
$action = New-Action1AutomationAction -Name 'Maintenance script' `
    -TemplateId run_script -ActionId 'existing_action_id' `
    -Parameters @{ run_script_id = 'maintenance_script_id' }
```

Preserves an existing action identity when reconstructing an action.

## PARAMETERS

### -Name

The action display name. Must be nonempty and non-whitespace.

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

### -TemplateId

The API action template ID, such as run_script, deploy_update, or deploy_package. Unknown nonempty IDs are allowed.

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

### -Parameters

A dictionary or PSCustomObject mapped to params. JSON strings, scalars, and null are rejected. Nested filters must be arrays of valid filter objects.

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ActionId

The action identity. Any nonempty, non-whitespace string is accepted, including older prefixed IDs.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: A new GUID
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

Returns one PSCustomObject containing the action definition. Nested parameter
objects retain their supplied references and types.

## NOTES

Construction does not sign the action or create a remote resource. API 4.0
signing applies to the completed automation configuration. The local templates
are examples of supported structure, not exhaustive API schemas.

## RELATED LINKS

[New-Action1AutomationActionFilter](New-Action1AutomationActionFilter.md)
[New-Action1AutomationDefinition](New-Action1AutomationDefinition.md)
[New-Action1AutomationScheduleDefinition](New-Action1AutomationScheduleDefinition.md)
