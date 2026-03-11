---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Start-Action1Requery

## SYNOPSIS

Triggers a requery operation to refresh specific data from Action1 endpoints or the organization.

## SYNTAX

```powershell
Start-Action1Requery [-Type] <String> [[-Endpoint_Id] <String>] [<CommonParameters>]
```

## DESCRIPTION

`Start-Action1Requery` triggers a requery request to the API to refresh specific datasets.  
Depending on the selected **Type**, the command may operate either organization-wide or for a specific endpoint.

The default organization must be set in advance via `Set-Action1DefaultOrg`.

This command sends a **POST** request to the appropriate API endpoint and instructs the service to regenerate or refresh the requested data.

Supported requery types include:

- **ReportData** – Regenerates report-related data.
- **InstalledSoftware** – Refreshes installed software inventory for endpoints.
- **InstalledUpdates** – Refreshes installed update information.

If the selected requery type supports endpoint targeting, an **Endpoint_Id** may be supplied.  
If not supplied, the requery will run at the organization level.

Authentication must be configured before using this command.

## EXAMPLES

### Example 1

```powershell
PS C:\> Start-Action1Requery -Type ReportData
```

Triggers default Action1 organization-wide refresh of the report data.

### Example 2

```powershell
PS C:\> Start-Action1Requery -Type InstalledSoftware -Endpoint_Id "12345"
```

Triggers a refresh of installed software information for the specified Action1 endpoint with Id "12345"

### Example 3

```powershell
PS C:\> PS C:\> Start-Action1Requery -Type InstalledUpdates
```

Triggers a refresh of installed update information for all applicable endpoints in the Action1 default organization.

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

Specifies the endpoint identifier for endpoint-specific data refresh.

If omitted, the operation is executed at the organization level.
If the selected requery type does not support endpoint targeting, the parameter is ignored and the request defaults to a default Action1 organization-wide operation.

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

### None. You cannot pipe objects to this command.

## OUTPUTS

### System.Object. Returns the API response from the requery request.

## NOTES

This command requires a valid authentication token to be set prior to execution.

Use the credentials configuration command before invoking API actions.

The default organization might be set in advance via `Set-Action1DefaultOrg`.

## RELATED LINKS

[Set-Action1Credentials](Set-Action1Credentials.md)

[Set-Action1DefaultOrg](Set-Action1DefaultOrg.md)
