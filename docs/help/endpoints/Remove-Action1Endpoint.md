---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Remove-Action1Endpoint

## SYNOPSIS

Deletes one managed endpoint from the current Action1 organization.

## SYNTAX

```
Remove-Action1Endpoint [-EndpointId] <String> [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

Deletes a specific managed endpoint by using the Action1 endpoints API.

The command uses the module default organization configured by **Set-Action1DefaultOrg**.

This command supports PowerShell confirmation. Use **-WhatIf** to preview the delete operation. Use **-Force** to bypass the confirmation prompt.

## EXAMPLES

### Example 1: Delete an endpoint

```powershell
Remove-Action1Endpoint -EndpointId '5e79941d-e4cc-40f3-899b-0cff63836d46'
```

Prompts for confirmation, then deletes the specified managed endpoint.

### Example 2: Preview endpoint deletion

```powershell
Remove-Action1Endpoint -EndpointId '5e79941d-e4cc-40f3-899b-0cff63836d46' -WhatIf
```

Shows what would be deleted without sending the DELETE request.

### Example 3: Delete without prompting

```powershell
Remove-Action1Endpoint -EndpointId '5e79941d-e4cc-40f3-899b-0cff63836d46' -Force
```

Deletes the managed endpoint without prompting for confirmation.

## PARAMETERS

### -EndpointId

Specifies the ID of the managed endpoint to delete.

The endpoint ID must use the standard GUID format, such as
`5e79941d-e4cc-40f3-899b-0cff63836d46`.

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

### -Force

Bypasses the confirmation prompt. **-WhatIf** is still honored when it is specified.

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

### None

You cannot pipe input to this command.

## OUTPUTS

### PSCustomObject

Returns a status object with EndpointId, Status, and Response. The Response value contains the raw response body returned by the DELETE request.

## NOTES

Requires permission to manage endpoints in Action1.

## RELATED LINKS

[Get-Action1Endpoint](Get-Action1Endpoint.md)
[Get-Action1Endpoints](Get-Action1Endpoints.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
