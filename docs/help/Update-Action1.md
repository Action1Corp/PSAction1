---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Update-Action1

## SYNOPSIS

Updates, modifies membership, or deletes Action1 objects.

## SYNTAX

```powershell
Update-Action1 [-Action] <String> [-Type] <String> [[-Data] <Object>] [[-Id] <String>]
 [[-AttributeName] <String>] [[-AttributeValue] <String>] [[-URI] <String>] [-Force] [<CommonParameters>]
```

## DESCRIPTION

`Update-Action1` performs update operations against Action1 objects exposed by the API.

Depending on the `-Action` and `-Type` parameters, the command can:

- Modify object properties.
- Modify membership of an endpoint group.
- Delete existing objects.
- Send a raw PATCH request to a specified URI.

The function builds the appropriate API endpoint path internally and sends the request using the module's internal API helper functions. Authentication must already be configured using `Set-Action1Credentials`.

For destructive actions such as `Delete`, the command prompts for confirmation unless the `-Force` switch is specified.

## EXAMPLES

### Example 1

```powershell
$data = [PSCustomObject]@{
    name = "NewEndpointName"
}

Update-Action1 -Action Modify -Type Endpoint -Id "endpoint-123" -Data $data
```

Updates the name of the Action1 endpoint with Id "endpoint-123".

### Example 2

```powershell
$data = [PSCustomObject]@{
    name = "Production Servers"
}

Update-Action1 -Action Modify -Type EndpointGroup -Id "group-42" -Data $data
```

Updates properties of the Action1 endpoint group with Id "group-42".

### Example 3

```powershell
$data = @{
    endpointIds = @("endpoint-1","endpoint-2")
}

Update-Action1 -Action ModifyMembers -Type EndpointGroup -Id "group-42" -Data $data
```

Adds or modifies members of the Action1 endpoint group with Id "group-42".

### Example 4

```powershell
Update-Action1 `
    -Action Modify `
    -Type CustomAttribute `
    -Id "endpoint-123" `
    -AttributeName "Owner" `
    -AttributeValue "IT"
```

Updates a custom attribute "Owner" for the specified Action1 endpoint with Id "endpoint-123".

### Example 5

```powershell
Update-Action1 -Action Delete -Type Automation -Id "auto-88"
```

Prompts for confirmation and deletes the specified Action1 automation object with Id "auto-88".

### Example 6

```powershell
Update-Action1 -Action Delete -Type Endpoint -Id "endpoint-123" -Force
```

Deletes Action1 endpoint with Id "endpoint-123" without prompting for confirmation.

### Example 7

```powershell
Update-Action1 -Action Modify -Type RawURI -URI "/v1/custom/path" -Data $data
```

Sends a PATCH request directly to the specified Action1 API URI "/v1/custom/path".

## PARAMETERS

### -Action

Specifies the type of operation to perform.

Allowed values:

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

### -Type

Specifies the target object type for the operation.

Allowed values:

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

### -Data

Object containing data to send in the API request body.

For `Modify` and `ModifyMembers`, this usually contains the updated properties or membership list.

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

### -Id

Identifier of the object being modified or deleted.

Required for most `Modify` and `Delete` operations.

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

### -AttributeName

Name of the custom attribute when updating an endpoint custom attribute.

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

Value to assign to the specified custom attribute.

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

### -URI

Raw API URI used when `-Type RawURI` is specified.

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

### -Force

Suppresses the confirmation prompt when performing `Delete` action.

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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None. You cannot pipe objects to this command.

## OUTPUTS

### System.Object Returns the response object from the API request.

## NOTES

The command requires a valid authentication token. Use **Set-Action1Credentials** cmdlet before executing API operations.

Some operations (such as endpoint updates) automatically filter allowed fields before sending the request to the API.

## RELATED LINKS
[Set-Action1Credentials](Set-Action1Credentials.md)
