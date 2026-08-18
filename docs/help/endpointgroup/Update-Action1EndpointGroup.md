---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Update-Action1EndpointGroup

## SYNOPSIS

Updates an endpoint group in the current Action1 organization.

## SYNTAX

### ByGroupId (Default)
```
Update-Action1EndpointGroup [-GroupId] <String> -EndpointGroupDefinition <Object> [-Force] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

### ByGroupName
```
Update-Action1EndpointGroup -GroupName <String> -EndpointGroupDefinition <Object> [-Force] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

## DESCRIPTION

Updates an endpoint group in the current Action1 organization by calling the
Action1 endpoint group API.

The command accepts an endpoint group ID or an endpoint group name. When
**-GroupName** is used, the command resolves the name by searching endpoint
groups in the current organization and then calls the endpoint group API path
with the resolved ID.

The **-EndpointGroupDefinition** value is sent as the request body without local
conversion. Supply the complete endpoint group definition expected by the Action1
API. Endpoint group PATCH behaves as a replacement-style update, so omitted
definition fields can remove or reset those settings in Action1.

The command does not validate the endpoint group definition schema locally; API
validation errors are returned by the Action1 request helper.

Use **-WhatIf** to preview the operation. Use **-Force** to bypass confirmation
prompts.

The command uses the module default organization configured by
**Set-Action1DefaultOrg**.

## EXAMPLES

### Example 1: Update an endpoint group by ID

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
        offline_alerts_enabled    = 'yes'
        offline_alerts_delay      = 20160
        online_alerts_enabled     = 'yes'
        user_ids_for_notification = @(
            '387a511f-8aac-4ec3-a8f2-47f2869e9500'
        )
    }
}

Update-Action1EndpointGroup `
    -GroupId 'Win10_1765215211802' `
    -EndpointGroupDefinition $endpointGroupDefinition
```

Updates the endpoint group with the supplied request body.

### Example 2: Update an endpoint group by name

```powershell
Update-Action1EndpointGroup `
    -GroupName 'Windows Workstations' `
    -EndpointGroupDefinition $endpointGroupDefinition `
    -Force
```

Resolves the endpoint group named Windows Workstations and updates it.

### Example 3: Update a group from an existing group definition

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

$endpointGroupDefinition.name = 'Windows 11 Workstations'
$endpointGroupDefinition.description = 'Adjusted group definition for Windows 11.'

Update-Action1EndpointGroup `
    -GroupId 'Win11_1765215211802' `
    -EndpointGroupDefinition $endpointGroupDefinition `
    -Force
```

Updates the selected endpoint group from definition fields copied from another
endpoint group. The copied definition fields can be updated before calling
**Update-Action1EndpointGroup**.

### Example 4: Update with a prepared endpoint group definition

```powershell
Update-Action1EndpointGroup `
    -GroupId 'Win10_1765215211802' `
    -EndpointGroupDefinition $endpointGroupDefinition `
    -Force
```

Passes the prepared endpoint group definition directly as the PATCH request body.

### Example 5: Preview an endpoint group update

```powershell
Update-Action1EndpointGroup `
    -GroupId 'Win10_1765215211802' `
    -EndpointGroupDefinition $endpointGroupDefinition `
    -WhatIf
```

Shows the update operation without sending the API request.

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

Specifies the endpoint group definition to send as the PATCH request body.

The command passes this object directly as the Action1 request body.

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

### -GroupId

Specifies the ID of the endpoint group to update.

Endpoint group IDs are opaque strings, not GUIDs.

```yaml
Type: String
Parameter Sets: ByGroupId
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -GroupName

Specifies the name of the endpoint group to update.

The command resolves the name by calling `Resolve-Action1EndpointGroupByName`.
If the name is not found or is not unique, the command writes a terminating
error.

```yaml
Type: String
Parameter Sets: ByGroupName
Aliases:

Required: True
Position: Named
Default value: None
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

Returns the Action1 API response for the updated endpoint group.

## NOTES

Requires the default Action1 organization to be configured with
**Set-Action1DefaultOrg**.

The command sends a PATCH request to the endpoint group API path:
`/endpoints/groups/:orgId/:groupId`.

## RELATED LINKS

[Get-Action1EndpointGroup](Get-Action1EndpointGroup.md)
[Get-Action1EndpointGroups](Get-Action1EndpointGroups.md)
[New-Action1EndpointGroup](New-Action1EndpointGroup.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
