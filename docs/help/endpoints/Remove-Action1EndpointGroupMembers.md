---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Remove-Action1EndpointGroupMembers

## SYNOPSIS

Removes multiple endpoints from an endpoint group in the current Action1 organization.

## SYNTAX

### ByGroupId (Default)
```
Remove-Action1EndpointGroupMembers [-GroupId] <String> -EndpointIds <String[]> [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### ByGroupName
```
Remove-Action1EndpointGroupMembers -GroupName <String> -EndpointIds <String[]> [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

Removes managed endpoints from a specific endpoint group by calling the Action1
endpoint group contents API once with one operation object per endpoint.

The command accepts an endpoint group ID or an endpoint group name. When
**-GroupName** is used, the command resolves the name by searching endpoint
groups in the current organization and then calls the endpoint group contents
API path with the resolved ID.

Each **-EndpointIds** value must use the standard GUID format. The command sends
an Action1 group-member operation for each endpoint ID with `method` set to
`DELETE` and `endpoint_id` set to the supplied endpoint ID.

Use **-WhatIf** to preview the operation. Use **-Force** to bypass confirmation
prompts.

The command uses the module default organization configured by
**Set-Action1DefaultOrg**.

## EXAMPLES

### Example 1: Remove endpoints from a group by ID

```powershell
$endpointIds = @(
    '5e79941d-e4cc-40f3-899b-0cff63836d46'
    '79e8ad16-70ec-42fe-8676-cfc1a47a5bc6'
)

Remove-Action1EndpointGroupMembers `
    -GroupId 'Service_1696554367754' `
    -EndpointIds $endpointIds
```

Removes the endpoints from the specified endpoint group in the current
organization.

### Example 2: Remove endpoints from a group by name

```powershell
Remove-Action1EndpointGroupMembers `
    -GroupName 'Workstations' `
    -EndpointIds @(
        '5e79941d-e4cc-40f3-899b-0cff63836d46'
        '79e8ad16-70ec-42fe-8676-cfc1a47a5bc6'
    )
```

Resolves the endpoint group named Workstations and removes the endpoints from
that group.

### Example 3: Preview the request

```powershell
Remove-Action1EndpointGroupMembers `
    -GroupId 'Service_1696554367754' `
    -EndpointIds $endpointIds `
    -WhatIf
```

Shows the remove operation without sending the API request.

## PARAMETERS

### -EndpointIds

Specifies the IDs of the endpoints to remove from the endpoint group.

Each value must use the standard GUID format.

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

Specifies the ID of the endpoint group that contains the endpoints.

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

Specifies the name of the endpoint group that contains the endpoints.

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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction,
-ErrorVariable, -InformationAction, -InformationVariable, -OutVariable,
-OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable.
For more information, see
[about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe input to this command.

## OUTPUTS

### System.Object

Returns the Action1 API response.

## NOTES

Requires the default Action1 organization to be configured with
**Set-Action1DefaultOrg**.

The command sends a POST request to the endpoint group contents API path:
`/endpoints/groups/:orgId/:groupId/contents`.

## RELATED LINKS

[Add-Action1EndpointGroupMembers](Add-Action1EndpointGroupMembers.md)
[Get-Action1EndpointGroup](Get-Action1EndpointGroup.md)
[Get-Action1EndpointGroups](Get-Action1EndpointGroups.md)
[Get-Action1EndpointGroupMembers](Get-Action1EndpointGroupMembers.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
