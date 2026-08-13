---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Add-Action1EndpointGroupMembers

## SYNOPSIS

Adds multiple endpoints to an endpoint group in the current Action1 organization.

## SYNTAX

### ByGroupIdEndpointIds (Default)
```
Add-Action1EndpointGroupMembers [-GroupId] <String> -EndpointIds <String[]> [-Force] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

### ByGroupIdEndpointObjects
```
Add-Action1EndpointGroupMembers [-GroupId] <String> -EndpointObjects <Object[]> [-Force] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

### ByGroupNameEndpointObjects
```
Add-Action1EndpointGroupMembers -GroupName <String> -EndpointObjects <Object[]> [-Force] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

### ByGroupNameEndpointIds
```
Add-Action1EndpointGroupMembers -GroupName <String> -EndpointIds <String[]> [-Force] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

## DESCRIPTION

Adds managed endpoints to a specific endpoint group by calling the Action1
endpoint group contents API once with one operation object per endpoint.

The command accepts an endpoint group ID or an endpoint group name. When
**-GroupName** is used, the command resolves the name by searching endpoint
groups in the current organization and then calls the endpoint group contents
API path with the resolved ID.

Each **-EndpointIds** value must use the standard GUID format. The command sends
an Action1 group-member operation for each endpoint ID with `method` set to
`POST`, `type` set to `Endpoint`, and `endpoint_id` set to the supplied endpoint
ID.

You can also pipe endpoint objects to the command. Piped endpoint objects must
include an `id` property that contains the endpoint GUID. The command collects
valid endpoint IDs from all pipeline input before sending a single API request.
Invalid piped objects are reported and skipped. If no valid endpoint IDs are
supplied, the command does not call the API.

Use **-WhatIf** to preview the operation. Use **-Force** to bypass confirmation
prompts.

The command uses the module default organization configured by
**Set-Action1DefaultOrg**.

## EXAMPLES

### Example 1: Add endpoints to a group by ID

```powershell
$endpointIds = @(
    '5e79941d-e4cc-40f3-899b-0cff63836d46'
    '79e8ad16-70ec-42fe-8676-cfc1a47a5bc6'
)

Add-Action1EndpointGroupMembers `
    -GroupId 'Service_1696554367754' `
    -EndpointIds $endpointIds
```

Adds the endpoints to the specified endpoint group in the current organization.

### Example 2: Add endpoints to a group by name

```powershell
Add-Action1EndpointGroupMembers `
    -GroupName 'Workstations' `
    -EndpointIds @(
        '5e79941d-e4cc-40f3-899b-0cff63836d46'
        '79e8ad16-70ec-42fe-8676-cfc1a47a5bc6'
    )
```

Resolves the endpoint group named Workstations and adds the endpoints to that
group.

### Example 3: Add piped group members to another group

```powershell
Get-Action1EndpointGroupMembers `
    -GroupName 'Pilot Workstations' `
    -Status Connected `
    -RebootRequired No `
    -OS 'Windows 11' |
    Add-Action1EndpointGroupMembers -GroupName 'Production Workstations'
```

Gets connected Windows 11 endpoints that do not require reboot from the Pilot
Workstations endpoint group, collects their endpoint IDs, and adds them to the
Production Workstations endpoint group with one API request.

### Example 4: Add filtered endpoints from the organization endpoint list

```powershell
Get-Action1Endpoints `
    -Status Connected `
    -RebootRequired Yes `
    -OS 'Windows Server' |
    Add-Action1EndpointGroupMembers -GroupName 'Servers Pending Reboot'
```

Gets connected Windows Server endpoints that require reboot from the current
organization and adds them to the Servers Pending Reboot endpoint group.

### Example 5: Preview the request

```powershell
Add-Action1EndpointGroupMembers `
    -GroupId 'Service_1696554367754' `
    -EndpointIds $endpointIds `
    -WhatIf
```

Shows the add operation without sending the API request.

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

### -EndpointIds

Specifies the IDs of the endpoints to add to the endpoint group.

Each value must use the standard GUID format.

```yaml
Type: String[]
Parameter Sets: ByGroupIdEndpointIds, ByGroupNameEndpointIds
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -EndpointObjects

Specifies endpoint objects to add to the endpoint group. The command accepts
these objects from the pipeline.

Each object must include an `id` property that contains a standard endpoint
GUID. Invalid objects are reported and skipped.

```yaml
Type: Object[]
Parameter Sets: ByGroupIdEndpointObjects, ByGroupNameEndpointObjects
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByValue)
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

Specifies the ID of the endpoint group that receives the endpoints.

Endpoint group IDs are opaque strings, not GUIDs.

```yaml
Type: String
Parameter Sets: ByGroupIdEndpointIds, ByGroupIdEndpointObjects
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -GroupName

Specifies the name of the endpoint group that receives the endpoints.

The command resolves the name by calling `Resolve-Action1EndpointGroupByName`.
If the name is not found or is not unique, the command writes a terminating
error.

```yaml
Type: String
Parameter Sets: ByGroupNameEndpointIds, ByGroupNameEndpointObjects
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

### System.Object

You can pipe endpoint objects with an `id` property to this command.

## OUTPUTS

### System.Object

Returns the Action1 API response.

## NOTES

Requires the default Action1 organization to be configured with
**Set-Action1DefaultOrg**.

The command sends a POST request to the endpoint group contents API path:
`/endpoints/groups/:orgId/:groupId/contents`.

## RELATED LINKS

[Get-Action1EndpointGroup](Get-Action1EndpointGroup.md)
[Get-Action1EndpointGroups](Get-Action1EndpointGroups.md)
[Get-Action1EndpointGroupMembers](Get-Action1EndpointGroupMembers.md)
[Get-Action1Endpoints](../endpoint/Get-Action1Endpoints.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
