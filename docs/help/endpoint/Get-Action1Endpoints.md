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
Get-Action1Endpoints [[-Status] <String>] [[-RebootRequired] <String>] [[-OS] <String>] [<CommonParameters>]
```

## DESCRIPTION

Gets managed endpoint records from the current Action1 organization by using the Action1 endpoints API.

Use **Status** to filter endpoints by connection or uninstall status.

Use **RebootRequired** to filter endpoints by reboot requirement.

Use **OS** to filter endpoints by operating system family.

Specify `All` for a filter parameter to skip that filter.

The command uses the module default organization configured by **Set-Action1DefaultOrg**.

## EXAMPLES

### Example 1: Get all endpoints

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
Get-Action1Endpoints -Status All
```

Gets managed endpoints without applying the status filter.

### Example 4: Get endpoints that require reboot

```powershell
Get-Action1Endpoints -Status All -RebootRequired Yes
```

Gets managed endpoints that require reboot, without applying the endpoint status filter.

### Example 5: Get Windows 11 endpoints that require reboot

```powershell
Get-Action1Endpoints -Status All -RebootRequired Yes -OS 'Windows 11'
```

Gets managed Windows 11 endpoints that require reboot.

### Example 6: Review selected endpoint fields

```powershell
Get-Action1Endpoints -Status Connected |
    Select-Object id, name, status, reboot_required, OS
```

Gets connected endpoints and selects key fields.

### Example 7: Add filtered endpoints to an endpoint group

```powershell
Get-Action1Endpoints `
    -Status Connected `
    -RebootRequired No `
    -OS 'Windows 11' |
    Add-Action1EndpointGroupMembers -GroupName 'Windows 11 Workstations'
```

Gets connected Windows 11 endpoints that do not require reboot, then pipes the
endpoint objects to **Add-Action1EndpointGroupMembers**. The receiving command
collects the endpoint IDs and sends one bulk API request to add them to the
endpoint group.

### Example 8: Preview adding filtered endpoints to an endpoint group

```powershell
Get-Action1Endpoints `
    -Status Connected `
    -RebootRequired Yes `
    -OS 'Windows Server' |
    Add-Action1EndpointGroupMembers `
        -GroupName 'Servers Pending Reboot' `
        -WhatIf
```

Gets connected Windows Server endpoints that require reboot, then previews the
endpoint group membership update without sending the add request.

## PARAMETERS

### -OS

Filters endpoints by operating system family.

Specify `All` to disable OS filtering.

Accepted values:

* `Windows 11`
* `Windows 10`
* `Windows Server`
* `macOS`
* `linux`
* `All`

```yaml
Type: String
Parameter Sets: (All)
Aliases:
Accepted values: Windows 11, Windows 10, Windows Server, macOS, linux, All

Required: False
Position: 2
Default value: All
Accept pipeline input: False
Accept wildcard characters: False
```

### -RebootRequired

Filters endpoints by reboot requirement.

Specify `All` to disable reboot requirement filtering.

Accepted values:

* `Yes`
* `No`
* `All`

```yaml
Type: String
Parameter Sets: (All)
Aliases:
Accepted values: Yes, No, All

Required: False
Position: 1
Default value: All
Accept pipeline input: False
Accept wildcard characters: False
```

### -Status

Filters endpoints by endpoint status.

Specify `All` to disable status filtering.

Accepted values:

* `Connected`
* `Disconnected`
* `Pending Uninstall`
* `All`

```yaml
Type: String
Parameter Sets: (All)
Aliases:
Accepted values: Connected, Disconnected, Pending Uninstall, All

Required: False
Position: 0
Default value: All
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

Returns managed endpoint objects from Action1. The objects include an `id`
property and can be piped to commands that accept endpoint objects, such as
**Add-Action1EndpointGroupMembers**.

## NOTES

Requires the default Action1 organization to be configured with **Set-Action1DefaultOrg**.

The command retrieves paged results from the Action1 API and returns endpoint objects to the pipeline.

## RELATED LINKS

[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
[Add-Action1EndpointGroupMembers](../endpointgroup/Add-Action1EndpointGroupMembers.md)
[Get-Action1EndpointGroupMembers](../endpointgroup/Get-Action1EndpointGroupMembers.md)
