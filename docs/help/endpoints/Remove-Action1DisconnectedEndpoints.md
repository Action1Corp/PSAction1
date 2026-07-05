---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Remove-Action1DisconnectedEndpoints

## SYNOPSIS

Deletes disconnected managed endpoints that have not been seen for a specified
number of days.

## SYNTAX

```
Remove-Action1DisconnectedEndpoints [[-DaysDisconnected] <Int32>] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

## DESCRIPTION

Gets disconnected managed endpoints from the current Action1 organization by
using **Get-Action1Endpoints -Status Disconnected**.

The command filters endpoints where **last_seen** is older than or equal to the
configured cutoff date, then removes matching endpoints by using
**Remove-Action1Endpoints**.

The command uses the module default organization configured by
**Set-Action1DefaultOrg**.

This command supports PowerShell confirmation. Use **-WhatIf** to preview the
delete operations. Use **-Confirm** to require confirmation before each endpoint
is removed.

## EXAMPLES

### Example 1: Remove default candidates

```powershell
Remove-Action1DisconnectedEndpoints
```

Gets disconnected endpoints, selects endpoints whose **last_seen** value is at
least 90 days old, prompts for confirmation, and removes the selected endpoints.

### Example 2: Use a 180-day cutoff

```powershell
Remove-Action1DisconnectedEndpoints -DaysDisconnected 180
```

Gets disconnected endpoints and removes endpoints that have not been seen for at
least 180 days.

### Example 3: Preview removal

```powershell
Remove-Action1DisconnectedEndpoints -DaysDisconnected 180 -WhatIf
```

Shows which disconnected endpoints would be removed without sending DELETE
requests.

### Example 4: Prompt before removal

```powershell
Remove-Action1DisconnectedEndpoints -DaysDisconnected 180 -Confirm
```

Prompts for confirmation before each matching endpoint is removed.

### Example 5: Review cleanup statistics

```powershell
$result = Remove-Action1DisconnectedEndpoints -DaysDisconnected 180
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

### -DaysDisconnected

Specifies how many days an endpoint must be disconnected before it is removed.

The command removes disconnected endpoints whose **last_seen** value is older
than or equal to the cutoff date calculated from this value.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 0
Default value: 90
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

Returns cleanup statistics with DisconnectedEndpointsProcessed,
EndpointsMatched, EndpointsRemovalSucceeded, EndpointsRemovalProcessed,
EndpointsRemoved, EndpointsSkipped, EndpointsFailed, and DaysDisconnected.

## NOTES

Requires permission to manage endpoints in Action1.

## RELATED LINKS

[Get-Action1Endpoints](Get-Action1Endpoints.md)
[Remove-Action1Endpoint](Remove-Action1Endpoint.md)
[Remove-Action1Endpoints](Remove-Action1Endpoints.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
