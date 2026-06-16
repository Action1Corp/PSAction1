---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Start-Action1Requery

## SYNOPSIS

Triggers an Action1 requery operation to refresh report, software inventory, or update data.

## SYNTAX

```
Start-Action1Requery [-Type] <String> [[-Endpoint_Id] <String>] [<CommonParameters>]
```

## DESCRIPTION

`Start-Action1Requery` sends a POST request to the Action1 API to refresh a supported dataset.

The command uses the module's internal URI map to build the correct requery endpoint for the selected **Type** value. Some requery operations run at the default organization level. Other operations can target a specific endpoint when **Endpoint_Id** is supplied.

If **Endpoint_Id** is specified for a requery type that does not support endpoint targeting, the command writes an error and continues by using the organization-wide requery endpoint.

Supported requery types are:

- **ReportData** - Refreshes report data.
- **InstalledSoftware** - Refreshes installed software inventory data.
- **InstalledUpdates** - Refreshes installed update data.

Authentication must be configured before using this command. For organization-scoped requery operations, the default Action1 organization must also be set.

## EXAMPLES

### Example 1

```powershell
PS C:\> Start-Action1Requery -Type ReportData
```

Triggers a refresh of report data for the default Action1 organization.

### Example 2

```powershell
PS C:\> Start-Action1Requery -Type InstalledSoftware -Endpoint_Id "12345"
```

Triggers a refresh of installed software inventory data for the specified Action1 endpoint.

### Example 3

```powershell
PS C:\> Start-Action1Requery -Type InstalledUpdates
```

Triggers a refresh of installed update data for the default Action1 organization.

## PARAMETERS

### -Type

Specifies the type of requery operation to perform.

Accepted values:

- ReportData
- InstalledSoftware
- InstalledUpdates

```yaml
Type: String
Parameter Sets: (All)
Aliases:
Accepted values: ReportData, InstalledSoftware, InstalledUpdates

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Endpoint_Id

Specifies the endpoint identifier for an endpoint-specific requery operation.

When this parameter is omitted, the command runs the requery at the organization level.

If the selected requery type does not support endpoint targeting, this parameter is ignored after an error is written, and the command continues by using the organization-wide requery endpoint.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
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

Returns the API response from the requery request.

## NOTES

This command requires a valid Action1 authentication token in the current session.

Use `Set-Action1Credentials` before invoking API actions.

For organization-scoped requests, set the default organization by using `Set-Action1DefaultOrg` before running this command.

## RELATED LINKS

[Set-Action1Credentials](Set-Action1Credentials.md)

[Set-Action1DefaultOrg](Set-Action1DefaultOrg.md)

[Get-Action1](Get-Action1.md)
