---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Export-Action1EndpointGroupsJson

## SYNOPSIS

Exports Action1 endpoint groups to a JSON file.

## SYNTAX

### AllEndpointGroups (Default)
```
Export-Action1EndpointGroupsJson [[-Path] <String>] [-PageSize <Int32>] [-Force]
 [<CommonParameters>]
```

### ByEndpointGroupIds
```
Export-Action1EndpointGroupsJson [[-Path] <String>] [-EndpointGroupIds <String[]>]
 [-PageSize <Int32>] [-Force] [<CommonParameters>]
```

### ByEndpointGroupNames
```
Export-Action1EndpointGroupsJson [[-Path] <String>] [-EndpointGroupNames <String[]>]
 [-PageSize <Int32>] [-Force] [<CommonParameters>]
```

## DESCRIPTION

`Export-Action1EndpointGroupsJson` calls `Get-Action1EndpointGroups` in page
mode, optionally filters each returned page by endpoint group ID or endpoint
group name, and exports the selected endpoint groups to a JSON file.

The command writes a single JSON object with the following top-level
properties:

* `schema`
* `datetime`
* `region`
* `enterprise_id`
* `organization_id`
* `type`
* `items`

The **schema** property is set to `PSAction1.EndpointGroup.v1`. The
**datetime** property contains the UTC export timestamp in the
`yyyy-MM-dd'T'HH:mm:ss'Z'` format. The **region** property is populated from
`Get-Action1Region`. The **enterprise_id** property is populated from
`Get-Action1EnterpriseId`. The **organization_id** property is populated from
`Get-Action1DefaultOrgId`. The **type** property is set to `EndpointGroup`.

The **items** array contains the endpoint group objects returned by
`Get-Action1EndpointGroups`. Item fields are not remapped, so all fields
returned by the source command are preserved in the JSON output.

Use either **EndpointGroupIds** or **EndpointGroupNames** to filter the export.
These parameters are mutually exclusive and cannot be used in the same command.
Endpoint group IDs are strings and are not validated as GUIDs.

Filtering is applied to each API page as it is returned. Pages that do not
contain matching endpoint groups are skipped, and later pages are still
requested until pagination is complete.

If a paged API response overlaps an earlier page, an endpoint group ID is
written only once.

Use **PageSize** to control how many endpoint groups are requested per API page.
The value must be from 1 through 200. The default page size is 200.

The command creates the target directory when it does not already exist and
overwrites the target JSON file if it already exists.

Use **Force** to write to the target file when file attributes, such as
read-only or hidden, would otherwise prevent writing. **Force** does not
override file locks or insufficient file system permissions.

## EXAMPLES

### Example 1: Export all endpoint groups to the default JSON file

```powershell
Export-Action1EndpointGroupsJson
```

Exports all endpoint groups returned by `Get-Action1EndpointGroups` page by
page to a timestamped JSON file in the current location.

### Example 2: Export all endpoint groups to a specific file

```powershell
Export-Action1EndpointGroupsJson -Path 'C:\Reports\EndpointGroups.json'
```

Exports all endpoint groups to the specified JSON file.

### Example 3: Export endpoint groups by ID

```powershell
Export-Action1EndpointGroupsJson `
    -Path 'C:\Reports\SelectedEndpointGroups.json' `
    -EndpointGroupIds 'Service_1696554367754'
```

Exports only endpoint groups whose `id` value matches one of the specified
endpoint group IDs.

### Example 4: Export endpoint groups by name

```powershell
Export-Action1EndpointGroupsJson `
    -Path 'C:\Reports\ServiceEndpointGroups.json' `
    -EndpointGroupNames 'Service'
```

Exports only endpoint groups whose `name` value matches one of the specified
endpoint group names.

### Example 5: Export to a read-only or hidden JSON file

```powershell
Export-Action1EndpointGroupsJson -Path 'C:\Reports\EndpointGroups.json' -Force
```

Exports endpoint groups and attempts to write to the target file even when file
attributes, such as read-only or hidden, would otherwise prevent writing.

## PARAMETERS

### -EndpointGroupIds

Specifies one or more endpoint group IDs to export.

Endpoint group IDs are strings, such as `Service_1696554367754`, and are not
required to use GUID format. Matching is case-insensitive. Empty or
whitespace-only values are ignored.

```yaml
Type: String[]
Parameter Sets: ByEndpointGroupIds
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -EndpointGroupNames

Specifies one or more endpoint group names to export.

Name matching is case-insensitive. Empty or whitespace-only values are ignored.

```yaml
Type: String[]
Parameter Sets: ByEndpointGroupNames
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

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

### -Path

Specifies the path to the JSON file to create.

If the path contains a directory that does not exist, the command creates the
directory. If the file already exists, the command overwrites it.

If the existing target file has read-only or hidden file attributes, use
**Force**.

If this parameter is not specified, the command creates a timestamped JSON file
in the current location using the
`Action1_<OrgName>_EndpointGroups_yyMMdd_HHmmssZ.json` naming format. The
organization name is read from `Get-Action1DefaultOrgName` and normalized with
`ConvertTo-LatinAlphaNumericString`. If normalization produces an empty value,
the default organization ID is used instead. The `Z` suffix marks the timestamp
as UTC.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PageSize

Specifies how many endpoint groups to request from Action1 per API page during
the JSON export.

The value must be from 1 through 200. The default value is 200.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 200
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
**Set-Action1DefaultOrg** and requires permission to view endpoint groups in
Action1.

## RELATED LINKS

[Get-Action1EndpointGroups](Get-Action1EndpointGroups.md)
[Get-Action1EndpointGroup](Get-Action1EndpointGroup.md)
[Get-Action1EnterpriseId](../enterprise/Get-Action1EnterpriseId.md)
[Get-Action1DefaultOrgId](../configuration/Get-Action1DefaultOrgId.md)
[Get-Action1DefaultOrgName](../configuration/Get-Action1DefaultOrgName.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
