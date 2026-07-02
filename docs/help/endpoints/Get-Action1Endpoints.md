---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1Endpoints

## SYNOPSIS

Gets managed endpoints for the current Action1 organization.

## SYNTAX

```
Get-Action1Endpoints [[-Status] <String>] [[-OnlineStatus] <String>] [[-UpdateStatus] <String>] [[-VulnerabilityStatus] <String>] [<CommonParameters>]
```

## DESCRIPTION

Gets managed endpoint records from the current Action1 organization by using the Action1 endpoints API.

Use **Status** to filter endpoints by connection or uninstall status.

Use **OnlineStatus**, **UpdateStatus**, and **VulnerabilityStatus** to filter endpoints by health status.

Specify an empty string or `$null` for a filter parameter to skip that filter.

The command uses the module default organization configured by **Set-Action1DefaultOrg**.

## EXAMPLES

### Example 1: Get disconnected endpoints

```powershell
Get-Action1Endpoints
```

Gets all endpoints in the current organization.

This is the default behavior.

### Example 2: Get connected endpoints

```powershell
Get-Action1Endpoints -Status Connected
```

Gets endpoints where the status is `Connected`.

### Example 3: Get endpoints without status filtering

```powershell
Get-Action1Endpoints -Status $null
```

Gets managed endpoints without applying the status filter.

### Example 4: Get endpoints with online warnings

```powershell
Get-Action1Endpoints -Status $null -OnlineStatus WARNING
```

Gets managed endpoints where the online status is `WARNING`, without applying the endpoint status filter.

### Example 5: Get endpoints with update and vulnerability errors

```powershell
Get-Action1Endpoints -Status $null -UpdateStatus ERROR -VulnerabilityStatus ERROR
```

Gets managed endpoints where the update status and vulnerability status are both `ERROR`.

### Example 6: Review selected endpoint fields

```powershell
Get-Action1Endpoints -Status Connected |
    Select-Object id, name, status, online_status, update_status, vulnerability_status
```

Gets connected endpoints and selects key fields.

## PARAMETERS

### -Status

Filters endpoints by endpoint status.

Specify an empty string or `$null` to disable status filtering.

Accepted values:

* `Connected`
* `Disconnected`
* `Pending Uninstall`

```yaml
Type: String
Parameter Sets: (All)
Aliases:
Accepted values: Connected, Disconnected, Pending Uninstall

Required: False
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OnlineStatus

Filters endpoints by online health status.

Specify an empty string or `$null` to disable online status filtering.

Accepted values:

* `SUCCESS`
* `WARNING`
* `ERROR`
* `UNDEFINED`

```yaml
Type: String
Parameter Sets: (All)
Aliases:
Accepted values: SUCCESS, WARNING, ERROR, UNDEFINED

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -UpdateStatus

Filters endpoints by update health status.

Specify an empty string or `$null` to disable update status filtering.

Accepted values:

* `SUCCESS`
* `WARNING`
* `ERROR`
* `UNDEFINED`

```yaml
Type: String
Parameter Sets: (All)
Aliases:
Accepted values: SUCCESS, WARNING, ERROR, UNDEFINED

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -VulnerabilityStatus

Filters endpoints by vulnerability health status.

Specify an empty string or `$null` to disable vulnerability status filtering.

Accepted values:

* `SUCCESS`
* `WARNING`
* `ERROR`
* `UNDEFINED`

```yaml
Type: String
Parameter Sets: (All)
Aliases:
Accepted values: SUCCESS, WARNING, ERROR, UNDEFINED

Required: False
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe input to this command.

## OUTPUTS

### System.Object

Returns managed endpoint objects from Action1.

## NOTES

Requires the default Action1 organization to be configured with **Set-Action1DefaultOrg**.

The command retrieves paged results from the Action1 API and returns endpoint objects to the pipeline.

## RELATED LINKS

[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
