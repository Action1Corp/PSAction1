---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Export-Action1EndpointGroupMembersJson

## SYNOPSIS

Exports endpoints from an Action1 endpoint group to a JSON file.

## SYNTAX

### ByGroupId (Default)
```
Export-Action1EndpointGroupMembersJson [-GroupId] <String> [-Status <String>] [-RebootRequired <String>]
 [-OS <String>] [-Path <String>] [-Force] [<CommonParameters>]
```

### ByGroupName
```
Export-Action1EndpointGroupMembersJson -GroupName <String> [-Status <String>] [-RebootRequired <String>]
 [-OS <String>] [-Path <String>] [-Force] [<CommonParameters>]
```

## DESCRIPTION

`Export-Action1EndpointGroupMembersJson` resolves one endpoint group by ID or
name, calls `Get-Action1EndpointGroupMembers` with the selected endpoint filters, and
exports the returned endpoint records to a JSON file.

The command writes a single JSON object with the following top-level
properties:

* `schema`
* `datetime`
* `region`
* `enterprise_id`
* `organization_id`
* `endpointgroup_id`
* `type`
* `items`

The **schema** property is set to `PSAction1.Endpoint.v1`. The **datetime**
property contains the UTC export timestamp in the
`yyyy-MM-dd'T'HH:mm:ss'Z'` format. The **region** property is populated from
`Get-Action1Region`. The **enterprise_id** property is populated from
`Get-Action1EnterpriseId`. The **organization_id** property is populated from
`Get-Action1DefaultOrgId`. The **endpointgroup_id** property contains the
resolved endpoint group ID. The **type** property is set to `Endpoint`.

The **items** array contains the endpoint objects returned by
`Get-Action1EndpointGroupMembers`. Item fields are not remapped, so all fields
returned by the source command are preserved in the JSON output.

Use **Status**, **RebootRequired**, and **OS** to pass endpoint filters through
to `Get-Action1EndpointGroupMembers`. Specify `All` for a filter parameter to skip
that filter.

The command creates the target directory when it does not already exist and
overwrites the target JSON file if it already exists.

Use **Force** to write to the target file when file attributes, such as
read-only or hidden, would otherwise prevent writing. **Force** does not
override file locks or insufficient file system permissions.

## EXAMPLES

### Example 1: Export endpoints from an endpoint group by ID

```powershell
Export-Action1EndpointGroupMembersJson -GroupId 'Service_1696554367754'
```

Exports all endpoints from the specified endpoint group to a timestamped JSON
file in the current location.

### Example 2: Export endpoints from an endpoint group to a specific file

```powershell
Export-Action1EndpointGroupMembersJson `
    -GroupId 'Service_1696554367754' `
    -Path 'C:\Reports\ServiceEndpointGroupMembers.json'
```

Exports endpoints from the specified endpoint group to the specified JSON file.

### Example 3: Export connected endpoints by endpoint group name

```powershell
Export-Action1EndpointGroupMembersJson `
    -GroupName 'Service' `
    -Status Connected
```

Resolves the endpoint group named Service and exports only connected endpoints
from that group.

### Example 4: Export Windows 11 endpoints that require reboot

```powershell
Export-Action1EndpointGroupMembersJson `
    -GroupName 'Workstations' `
    -Status All `
    -RebootRequired Yes `
    -OS 'Windows 11'
```

Exports managed Windows 11 endpoints that require reboot from the endpoint
group named Workstations.

### Example 5: Export to a read-only or hidden JSON file

```powershell
Export-Action1EndpointGroupMembersJson `
    -GroupId 'Service_1696554367754' `
    -Path 'C:\Reports\ServiceEndpointGroupMembers.json' `
    -Force
```

Exports endpoint group members and attempts to write to the target file even
when file attributes, such as read-only or hidden, would otherwise prevent
writing.

## PARAMETERS

### -Force

Forces the command to write to the target JSON file when file attributes, such
as read-only or hidden, would otherwise prevent writing.

This parameter does not override file locks or insufficient file system
permissions. Close the file if it is open in another application, such as
Windows Notepad, and verify that you have write permission to the target
location.

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

### -GroupId

Specifies the ID of the endpoint group whose endpoints are exported.

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

Specifies the name of the endpoint group whose endpoints are exported.

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

### -Path

Specifies the path to the JSON file to create.

If the path contains a directory that does not exist, the command creates the
directory. If the file already exists, the command overwrites it.

If the existing target file has read-only or hidden file attributes, use
**Force**.

If this parameter is not specified, the command creates a timestamped JSON file
in the current location using the
`Action1_<OrgName>_EndpointGroupMembers_<EndpointGroupId>_yyMMdd_HHmmssZ.json`
naming format. The organization name is read from `Get-Action1DefaultOrgName`
and normalized with `ConvertTo-LatinAlphaNumericString`. If normalization
produces an empty value, the default organization ID is used instead. The
endpoint group ID is included in the file name after removing characters that
are invalid in Windows file names. The `Z` suffix marks the timestamp as UTC.

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

### None

This command does not return pipeline output. It creates or overwrites a JSON
file at the specified path.

## NOTES

Requires the default Action1 organization to be configured with
**Set-Action1DefaultOrg** and requires permission to view endpoint groups and
endpoint group contents in Action1.

## RELATED LINKS

[Get-Action1EndpointGroupMembers](Get-Action1EndpointGroupMembers.md)
[Get-Action1EndpointGroup](Get-Action1EndpointGroup.md)
[Get-Action1EndpointGroups](Get-Action1EndpointGroups.md)
[Get-Action1EnterpriseId](../enterprise/Get-Action1EnterpriseId.md)
[Get-Action1DefaultOrgId](../configuration/Get-Action1DefaultOrgId.md)
[Get-Action1DefaultOrgName](../configuration/Get-Action1DefaultOrgName.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
