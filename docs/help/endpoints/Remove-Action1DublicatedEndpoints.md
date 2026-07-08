---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Remove-Action1DublicatedEndpoints

## SYNOPSIS

Deletes duplicated managed endpoints that share the same MAC address.

## SYNTAX

```
Remove-Action1DublicatedEndpoints [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

Gets all managed endpoints from the current Action1 organization by using
**Get-Action1Endpoints -Status All**.

The command groups endpoints by **MAC**, compares **last_seen** values, keeps
the newest endpoint for each MAC address, and removes older duplicates by using
**Remove-Action1Endpoints**.

Endpoints missing **id**, **MAC**, or **last_seen**, or endpoints with an
unparseable **last_seen** value, are skipped and counted as invalid.

The command uses the module default organization configured by
**Set-Action1DefaultOrg**.

This command supports PowerShell confirmation. Use **-WhatIf** to preview the
delete operations. Use **-Confirm** to require confirmation before each endpoint
is removed.

## EXAMPLES

### Example 1: Remove duplicated endpoints

```powershell
Remove-Action1DublicatedEndpoints
```

Gets all endpoints, keeps the newest endpoint for each MAC address, prompts for
confirmation, and removes older duplicated endpoints.

### Example 2: Preview removal

```powershell
Remove-Action1DublicatedEndpoints -WhatIf
```

Shows which duplicated endpoints would be removed without sending DELETE
requests.

### Example 3: Prompt before removal

```powershell
Remove-Action1DublicatedEndpoints -Confirm
```

Prompts for confirmation before each duplicated endpoint is removed.

### Example 4: Review cleanup statistics

```powershell
$result = Remove-Action1DublicatedEndpoints
$result | Format-List
```

Runs the cleanup and displays the summary statistics returned by the command.

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

Returns cleanup statistics with EndpointsTotal, EndpointsDuplicated,
EndpointsRemovalSucceeded, EndpointsRemovalProcessed, EndpointsRemoved,
EndpointsSkipped, EndpointsFailed, and EndpointsInvalid.

## NOTES

Requires permission to manage endpoints in Action1.

## RELATED LINKS

[Get-Action1Endpoints](Get-Action1Endpoints.md)
[Remove-Action1Endpoint](Remove-Action1Endpoint.md)
[Remove-Action1Endpoints](Remove-Action1Endpoints.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
