---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# New-Action1EndpointGroup

## SYNOPSIS

Creates an endpoint group in the current Action1 organization.

## SYNTAX

```
New-Action1EndpointGroup [-EndpointGroupDefinition] <Object> [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

Creates an endpoint group in the current Action1 organization by calling the
Action1 endpoint groups API.

The **-EndpointGroupDefinition** value is sent as the endpoint group definition
without local conversion. Supply the request definition expected by the Action1 API,
for example an endpoint group object without response-only fields such as `id`,
`type`, `self`, and `contents`.

The command does not validate the endpoint group definition schema locally; API
validation errors are returned by the Action1 request helper.

The command prompts for confirmation before creating an endpoint group. Use
**-WhatIf** to preview the operation. Use **-Force** to bypass confirmation
prompts.

The command uses the module default organization configured by
**Set-Action1DefaultOrg**.

## EXAMPLES

### Example 1: Create an endpoint group from an object

```powershell
$endpointGroupDefinition = [pscustomobject][ordered]@{
    name                 = 'My Endpoint Group'
    description          = 'Windows endpoints online within the last 30 days.'
    include_filter       = @(
        [pscustomobject][ordered]@{
            field_name  = 'OS'
            field_value = 'Windows 11'
            mode        = 'include'
        }
        [pscustomobject][ordered]@{
            field_name  = 'OS'
            field_value = 'Windows 10'
            mode        = 'include'
        }
        [pscustomobject][ordered]@{
            field_name  = 'last_seen'
            field_value = '-43200'
            mode        = 'include'
        }
    )
    include_filter_logic = '(1 OR 2) AND 3'
    exclude_filter       = @(
        [pscustomobject][ordered]@{
            field_name  = 'address'
            field_value = '192.168.1.0/24'
            mode        = 'include'
        }
        [pscustomobject][ordered]@{
            field_name  = 'address'
            field_value = '10.0.10.50-10.0.10.100'
            mode        = 'include'
        }
    )
    exclude_filter_logic = '1 OR 2'
    uptime_alerts        = [pscustomobject][ordered]@{
        offline_alerts_enabled  = 'yes'
        offline_alerts_delay    = 20160
        online_alerts_enabled   = 'yes'
        user_ids_for_notification = @(
            '387a511f-8aac-4ec3-a8f2-47f2869e9500'
        )
    }
}

New-Action1EndpointGroup -EndpointGroupDefinition $endpointGroupDefinition
```

Creates the endpoint group in the current organization.

### Example 2: Create a group from an existing group definition

```powershell
$sourceGroup = Get-Action1EndpointGroup -GroupName 'Windows 10'
$endpointGroupDefinition = $sourceGroup |
    Select-Object `
        name,
        description,
        include_filter,
        include_filter_logic,
        exclude_filter,
        exclude_filter_logic,
        uptime_alerts

$endpointGroupDefinition.name = 'Windows 10 Copy'
$endpointGroupDefinition.description = 'Copied and adjusted Windows 10 group.'

New-Action1EndpointGroup -EndpointGroupDefinition $endpointGroupDefinition -Force
```

Creates a new endpoint group from selected definition fields. The copied
definition fields can be updated before creating the new endpoint group.

### Example 3: Create another endpoint group definition

```powershell
New-Action1EndpointGroup `
    -EndpointGroupDefinition $anotherEndpointGroupDefinition `
    -Force
```

Creates another endpoint group without prompting for confirmation.

### Example 4: Preview endpoint group creation

```powershell
New-Action1EndpointGroup `
    -EndpointGroupDefinition $endpointGroupDefinition `
    -WhatIf
```

Shows the create operation without sending the API request.

## PARAMETERS

### -Confirm
Prompts you for confirmation before running the cmdlet.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -EndpointGroupDefinition

Specifies the endpoint group definition to create.

The command passes this object directly as the Action1 request body.

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Force

Suppresses confirmation prompts. This parameter does not override **-WhatIf**.

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

### -WhatIf
Shows what would happen if the cmdlet runs. The cmdlet is not run.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: wi

Required: False
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

### System.Object

Returns the Action1 API response for the created endpoint group.

## NOTES

Requires the default Action1 organization to be configured with
**Set-Action1DefaultOrg**.

The command sends a POST request to the endpoint groups API path:
`/endpoints/groups/:orgId`.

## RELATED LINKS

[Get-Action1EndpointGroup](Get-Action1EndpointGroup.md)
[Get-Action1EndpointGroups](Get-Action1EndpointGroups.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
