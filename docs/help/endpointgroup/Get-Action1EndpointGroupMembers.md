---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1EndpointGroupMembers

## SYNOPSIS

Gets endpoints from an endpoint group in the current Action1 organization.

## SYNTAX

### ByGroupId (Default)
```
Get-Action1EndpointGroupMembers [-GroupId] <String> [-Status <String>] [-RebootRequired <String>]
 [-OS <String>] [<CommonParameters>]
```

### ByGroupName
```
Get-Action1EndpointGroupMembers -GroupName <String> [-Status <String>] [-RebootRequired <String>]
 [-OS <String>] [<CommonParameters>]
```

## DESCRIPTION

Gets endpoint records included in a specific endpoint group by using the Action1
endpoint groups API.

The command accepts an endpoint group ID or an endpoint group name. When
**-GroupName** is used, the command resolves the name by searching endpoint
groups in the current organization and then calls the endpoint group contents
API path with the resolved ID.

Use **Status** to filter endpoints by connection or uninstall status.

Use **RebootRequired** to filter endpoints by reboot requirement.

Use **OS** to filter endpoints by operating system family.

Specify `All` for a filter parameter to skip that filter.

The command uses the module default organization configured by
**Set-Action1DefaultOrg**.

## EXAMPLES

### Example 1: Get endpoints from an endpoint group by ID

```powershell
Get-Action1EndpointGroupMembers -GroupId 'Service_1696554367754'
```

Gets all endpoints included in the specified endpoint group in the current
organization.

### Example 2: Get connected endpoints from an endpoint group

```powershell
Get-Action1EndpointGroupMembers -GroupId 'Service_1696554367754' -Status Connected
```

Gets connected endpoints included in the specified endpoint group.

### Example 3: Get endpoints from an endpoint group by name

```powershell
Get-Action1EndpointGroupMembers -GroupName 'Service'
```

Resolves the endpoint group named Service and gets endpoints included in that
group.

### Example 4: Get Windows 11 endpoints that require reboot

```powershell
Get-Action1EndpointGroupMembers `
    -GroupName 'Workstations' `
    -Status All `
    -RebootRequired Yes `
    -OS 'Windows 11'
```

Gets managed Windows 11 endpoints that require reboot from the endpoint group
named Workstations.

### Example 5: Review selected endpoint fields

```powershell
Get-Action1EndpointGroupMembers -GroupName 'Workstations' |
    Select-Object id, name, status, reboot_required, OS, added_via
```

Gets endpoints from the endpoint group and selects key fields.

## PARAMETERS

### -GroupId

Specifies the ID of the endpoint group whose endpoints are retrieved.

```yaml
Type: String
Parameter Sets: ByGroupId
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -GroupName

Specifies the name of the endpoint group whose endpoints are retrieved.

The command resolves the name by calling `Resolve-Action1EndpointGroupByName`.
If the name is not found or is not unique, the command writes a terminating
error.

```yaml
Type: String
Parameter Sets: ByGroupName
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

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
Position: Named
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
Position: Named
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
Position: Named
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

Returns endpoint objects from Action1.

## NOTES

Requires the default Action1 organization to be configured with
**Set-Action1DefaultOrg**.

The command retrieves paged results from the Action1 API and returns endpoint
objects to the pipeline. Action1 may include an `added_via` attribute on each
endpoint to indicate how the endpoint came to this group.

## RELATED LINKS

[Get-Action1EndpointGroup](Get-Action1EndpointGroup.md)
[Get-Action1EndpointGroups](Get-Action1EndpointGroups.md)
[Get-Action1Endpoints](Get-Action1Endpoints.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
