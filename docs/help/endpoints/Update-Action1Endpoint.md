---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Update-Action1Endpoint

## SYNOPSIS

Updates the name or comment of one managed endpoint in the current Action1 organization.

## SYNTAX

### ByEndpointId (Default)
```
Update-Action1Endpoint [-EndpointId] <String> [-Name <String>] [-Comment <String>] [-Force] [-WhatIf]
 [-Confirm] [<CommonParameters>]
```

### ByEndpointObject
```
Update-Action1Endpoint -EndpointObject <Object> [-Name <String>] [-Comment <String>] [-Force] [-WhatIf]
 [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

Updates a specific managed endpoint by using the Action1 endpoints API.

The command accepts an endpoint ID or an endpoint object with an **id** property.
When the endpoint object includes **name**, the name is included in
confirmation, debug, and error information.

The command uses the module default organization configured by **Set-Action1DefaultOrg**.

Specify at least one value to update: **-Name** or **-Comment**. You can specify both
parameters in the same command.

This command supports PowerShell confirmation. Use **-WhatIf** to preview the update
operation without sending the PATCH request. Use **-Confirm** to prompt for confirmation
before sending the PATCH request. Use **-Force** to bypass confirmation prompts.

## EXAMPLES

### Example 1: Update an endpoint name

```powershell
Update-Action1Endpoint `
    -EndpointId '5e79941d-e4cc-40f3-899b-0cff63836d46' `
    -Name 'Accounting-Laptop-01'
```

Updates the name of the specified managed endpoint.

### Example 2: Update an endpoint comment

```powershell
Update-Action1Endpoint `
    -EndpointId '5e79941d-e4cc-40f3-899b-0cff63836d46' `
    -Comment 'Assigned to the accounting department.'
```

Updates the comment of the specified managed endpoint.

### Example 3: Update an endpoint name and comment

```powershell
Update-Action1Endpoint `
    -EndpointId '5e79941d-e4cc-40f3-899b-0cff63836d46' `
    -Name 'Accounting-Laptop-01' `
    -Comment 'Assigned to the accounting department.'
```

Updates both the name and comment of the specified managed endpoint.

### Example 4: Preview an endpoint update

```powershell
Update-Action1Endpoint `
    -EndpointId '5e79941d-e4cc-40f3-899b-0cff63836d46' `
    -Name 'Accounting-Laptop-01' `
    -WhatIf
```

Shows what would be updated without sending the PATCH request.

### Example 5: Prompt before updating an endpoint

```powershell
Update-Action1Endpoint `
    -EndpointId '5e79941d-e4cc-40f3-899b-0cff63836d46' `
    -Comment 'Assigned to the accounting department.' `
    -Confirm
```

Prompts for confirmation before sending the PATCH request.

### Example 6: Update an endpoint object

```powershell
$endpoint = Get-Action1Endpoint -EndpointId '5e79941d-e4cc-40f3-899b-0cff63836d46'
Update-Action1Endpoint -EndpointObject $endpoint -Comment 'Assigned to accounting.'
```

Updates the endpoint object by using its **id** property.

### Example 7: Preview an endpoint update from the pipeline

```powershell
Get-Action1Endpoint -EndpointId '5e79941d-e4cc-40f3-899b-0cff63836d46' |
    Update-Action1Endpoint -Name 'Accounting-Laptop-01' -WhatIf
```

Gets the endpoint object and shows the update operation without sending the
PATCH request.

### Example 8: Update an endpoint without prompting

```powershell
Update-Action1Endpoint `
    -EndpointId '5e79941d-e4cc-40f3-899b-0cff63836d46' `
    -Comment 'Assigned to the accounting department.' `
    -Force
```

Updates the endpoint comment without prompting for confirmation.

## PARAMETERS

### -Comment

Specifies the new endpoint comment.

Specify **-Comment**, **-Name**, or both. The command writes an error when neither
parameter is specified.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Confirm

Prompts you for confirmation before running the command.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -EndpointId

Specifies the ID of the managed endpoint to update.

The endpoint ID must use the standard GUID format, such as
`5e79941d-e4cc-40f3-899b-0cff63836d46`.

```yaml
Type: String
Parameter Sets: ByEndpointId
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -EndpointObject

Specifies the managed endpoint object to update.

The object must include an **id** property. If the object includes a **name**
property, the name is included in confirmation, debug, and error information.

```yaml
Type: Object
Parameter Sets: ByEndpointObject
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -Force

Bypasses confirmation prompts. **-WhatIf** is still honored when it is specified.

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

### -Name

Specifies the new endpoint name.

Specify **-Name**, **-Comment**, or both. The command writes an error when neither
parameter is specified.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIf

Shows what would happen if the command runs. The command is not run.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: wi

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.Object

You can pipe endpoint objects with an **id** property to this command.

## OUTPUTS

### System.Object

Returns the updated endpoint object returned by Action1.

## NOTES

Requires permission to manage endpoints in Action1.

## RELATED LINKS

[Get-Action1Endpoint](Get-Action1Endpoint.md)
[Get-Action1Endpoints](Get-Action1Endpoints.md)
[Remove-Action1Endpoint](Remove-Action1Endpoint.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
