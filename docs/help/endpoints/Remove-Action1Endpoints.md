---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Remove-Action1Endpoints

## SYNOPSIS

Deletes multiple managed endpoints from the current Action1 organization.

## SYNTAX

```
Remove-Action1Endpoints [-EndpointIds] <String[]> [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

## DESCRIPTION

Deletes managed endpoints by using the Action1 endpoints API.

The command accepts endpoint IDs, validates each ID, shows progress, asks for
PowerShell confirmation, and removes valid endpoints by using
**Remove-Action1Endpoint**.

The command uses the module default organization configured by
**Set-Action1DefaultOrg**.

Use **-WhatIf** to preview the delete operations. Use **-Confirm** to require
confirmation before each endpoint is removed.

## EXAMPLES

### Example 1: Remove endpoints

```powershell
$endpointIds = @(
    '5e79941d-e4cc-40f3-899b-0cff63836d46'
    'f93c2a28-9a31-4633-8902-63f130b8a455'
)

Remove-Action1Endpoints -EndpointIds $endpointIds
```

Prompts for confirmation, then removes the specified managed endpoints.

### Example 2: Preview endpoint removal

```powershell
Remove-Action1Endpoints -EndpointIds $endpointIds -WhatIf
```

Shows which endpoints would be removed without sending DELETE requests.

### Example 3: Review removal statistics

```powershell
$result = Remove-Action1Endpoints -EndpointIds $endpointIds
$result | Format-List
```

Runs the removal and displays the summary statistics returned by the command.

## PARAMETERS

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

### -EndpointIds

Specifies the IDs of the managed endpoints to delete.

Each endpoint ID must use the standard GUID format, such as
`5e79941d-e4cc-40f3-899b-0cff63836d46`.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
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
This cmdlet supports the common parameters: -Debug, -ErrorAction,
-ErrorVariable, -InformationAction, -InformationVariable, -OutVariable,
-OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable.
For more information, see
[about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe input to this command.

## OUTPUTS

### PSCustomObject

Returns removal statistics with Succeeded, EndpointsRequested,
EndpointsRemovalProcessed, EndpointsRemoved, EndpointsSkipped,
EndpointsFailed, and EndpointsInvalid.

## NOTES

Requires permission to manage endpoints in Action1.

## RELATED LINKS

[Get-Action1Endpoint](Get-Action1Endpoint.md)
[Get-Action1Endpoints](Get-Action1Endpoints.md)
[Remove-Action1Endpoint](Remove-Action1Endpoint.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
