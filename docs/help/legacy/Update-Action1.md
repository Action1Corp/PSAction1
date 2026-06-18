---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Update-Action1

## SYNOPSIS

Updates, modifies endpoint group membership, or deletes Action1 objects.

## SYNTAX

```
Update-Action1 [-Action] <String> [-Type] <String> [[-Data] <Object>] [[-Id] <String>]
 [[-AttributeName] <String>] [[-AttributeValue] <String>] [[-URI] <String>] [-Force] [<CommonParameters>]
```

## DESCRIPTION

`Update-Action1` performs update operations against Action1 objects exposed through the Action1 API.

Depending on the values of the **Action** and **Type** parameters, the command can:

- Modify properties of endpoints, endpoint groups, and automations.
- Modify endpoint group membership.
- Update an endpoint custom attribute.
- Delete endpoints, endpoint groups, and automations.
- Send a raw PATCH request to a specified API URI.

The function builds the appropriate API endpoint path internally and sends the request by using the module's internal API helper functions.
Authentication must be configured in advance by using `Set-Action1Credentials`.
For operations that target organization resources, the default organization must be configured in advance by using `Set-Action1DefaultOrg`.

For destructive actions such as `Delete`, the command prompts for confirmation unless the **Force** switch is specified.

When **Type** is `RawURI`, the command sends a PATCH request directly to the URI specified by the **URI** parameter.

## EXAMPLES

### Example 1: Rename an endpoint

```powershell
$data = [PSCustomObject]@{
    name = 'NewEndpointName'
}

Update-Action1 -Action Modify -Type Endpoint -Id 'endpoint-123' -Data $data
```

Updates the name of the Action1 endpoint with the ID `endpoint-123`.

### Example 2: Update an endpoint comment

```powershell
$data = [PSCustomObject]@{
    comment = 'Managed by the infrastructure team'
}

Update-Action1 -Action Modify -Type Endpoint -Id 'endpoint-123' -Data $data
```

Updates the comment for the Action1 endpoint with the ID `endpoint-123`.

### Example 3: Update an endpoint group

```powershell
$data = [PSCustomObject]@{
    name = 'Production Servers'
}

Update-Action1 -Action Modify -Type EndpointGroup -Id 'group-42' -Data $data
```

Updates properties of the Action1 endpoint group with the ID `group-42`.

### Example 4: Modify endpoint group membership

```powershell
$data = @{
    endpointIds = @('endpoint-1', 'endpoint-2')
}

Update-Action1 -Action ModifyMembers -Type EndpointGroup -Id 'group-42' -Data $data
```

Sends endpoint membership data for the Action1 endpoint group with the ID `group-42`.

### Example 5: Update an endpoint custom attribute

```powershell
Update-Action1 -Action Modify -Type CustomAttribute -Id 'endpoint-123' -AttributeName 'Owner' -AttributeValue 'IT'
```

Sets the custom attribute named `Owner` to `IT` on the Action1 endpoint with the ID `endpoint-123`.

### Example 6: Delete an automation after confirmation

```powershell
Update-Action1 -Action Delete -Type Automation -Id 'auto-88'
```

Prompts for confirmation and deletes the Action1 automation with the ID `auto-88` if the operation is confirmed.

### Example 7: Delete an endpoint without prompting

```powershell
Update-Action1 -Action Delete -Type Endpoint -Id 'endpoint-123' -Force
```

Deletes the Action1 endpoint with the ID `endpoint-123` without prompting for confirmation.

### Example 8: Send a raw PATCH request

```powershell
$data = [PSCustomObject]@{
    name = 'Updated object name'
}

Update-Action1 -Action Modify -Type RawURI -URI '/v1/custom/path' -Data $data
```

Sends a PATCH request directly to the Action1 API URI `/v1/custom/path`.

## PARAMETERS

### -Action

Specifies the type of operation to perform.

Accepted values are:

- Modify
- ModifyMembers
- Delete

```yaml
Type: String
Parameter Sets: (All)
Aliases:
Accepted values: Modify, ModifyMembers, Delete

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AttributeName

Specifies the name of the custom attribute to update.

This parameter is used when **Action** is `Modify` and **Type** is `CustomAttribute`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AttributeValue

Specifies the value to assign to the custom attribute.

This parameter is used when **Action** is `Modify` and **Type** is `CustomAttribute`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Data

Specifies the request body sent to the API.

For `Modify` operations, this parameter contains the properties to update.
When modifying endpoints, only the `name` and `comment` properties are sent to the API.
For `ModifyMembers` operations, this parameter contains endpoint group membership data.
For `RawURI` requests, this parameter contains the raw PATCH request body.

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Force

Suppresses the confirmation prompt when performing a `Delete` action.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Id

Specifies the identifier of the Action1 object being modified or deleted.

This parameter is required by the function logic for most `Modify` operations and is also needed for `ModifyMembers` and `Delete` operations that target a specific object.
For `CustomAttribute` updates, this parameter specifies the endpoint ID.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Type

Specifies the target object type for the operation.

Accepted values are:

- EndpointGroup
- Endpoint
- Automation
- CustomAttribute
- RawURI

```yaml
Type: String
Parameter Sets: (All)
Aliases:
Accepted values: EndpointGroup, Endpoint, Automation, CustomAttribute, RawURI

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -URI

Specifies the raw API URI to send the request to.

This parameter is required when **Type** is `RawURI`.
When **Type** is `RawURI`, the function sends a PATCH request directly to this URI and bypasses the internal URI lookup table.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe objects to this command.

## OUTPUTS

### System.Object

Returns the response object from the Action1 API request.

## NOTES

The command requires a valid authentication token. Use `Set-Action1Credentials` before running API operations.

For operations that target organization resources, configure the default organization by using `Set-Action1DefaultOrg`.

Endpoint modifications automatically remove properties other than `name` and `comment` from the request body before sending the request to the API.

`Delete` operations prompt for confirmation unless the **Force** switch is specified.

## RELATED LINKS

[Get-Action1](Get-Action1.md)

[New-Action1](New-Action1.md)

[Set-Action1Credentials](Set-Action1Credentials.md)

[Set-Action1DefaultOrg](Set-Action1DefaultOrg.md)
