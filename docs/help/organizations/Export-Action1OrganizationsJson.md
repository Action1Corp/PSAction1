---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Export-Action1OrganizationsJson

## SYNOPSIS

Exports Action1 organizations to a JSON file.

## SYNTAX

### AllOrganizations (Default)
```
Export-Action1OrganizationsJson [[-Path] <String>] [-Force] [<CommonParameters>]
```

### ByOrgIds
```
Export-Action1OrganizationsJson [[-Path] <String>] [-OrgIds <String[]>] [-Force] [<CommonParameters>]
```

### ByOrgNames
```
Export-Action1OrganizationsJson [[-Path] <String>] [-OrgNames <String[]>] [-Force] [<CommonParameters>]
```

## DESCRIPTION

`Export-Action1OrganizationsJson` calls `Get-Action1Organizations`,
optionally filters the returned organization list by organization ID or
organization name, and exports the selected organizations to a JSON file.

The command writes a single JSON object with the following top-level
properties:

* `schema`
* `datetime`
* `region`
* `enterprise_id`
* `type`
* `items`

The **schema** property is set to `PSAction1.Organization.v1`. The
**datetime** property contains the UTC export timestamp in the
`yyyy-MM-dd'T'HH:mm:ss'Z'` format. The **region** property is populated from
`Get-Action1Region`. The **enterprise_id** property is populated from
`Get-Action1EnterpriseId`. The **type** property is set to `Organization`.

Each item in the **items** array contains these properties in this order:

* `id`
* `type`
* `self`
* `name`
* `description`
* `enterprise_id`

The **self** value is built from the configured Action1 API base URI and the
organization ID.

Use either **OrgIds** or **OrgNames** to filter the export. These parameters are
mutually exclusive and cannot be used in the same command.

The command creates the target directory when it does not already exist and
overwrites the target JSON file if it already exists.

Use **Force** to write to the target file when file attributes, such as
read-only or hidden, would otherwise prevent writing. **Force** does not
override file locks or insufficient file system permissions.

## EXAMPLES

### Example 1: Export all organizations to the default JSON file

```powershell
Export-Action1OrganizationsJson
```

Exports all organizations returned by `Get-Action1Organizations` to a
timestamped JSON file in the current location.

### Example 2: Export all organizations to a specific file

```powershell
Export-Action1OrganizationsJson -Path 'C:\Reports\Organizations.json'
```

Exports all organizations to the specified JSON file.

### Example 3: Export organizations by ID

```powershell
Export-Action1OrganizationsJson `
    -Path 'C:\Reports\SelectedOrganizations.json' `
    -OrgIds '88c8b425-871e-4ff6-9afc-00df8592c6db'
```

Exports only organizations whose `id` value matches one of the specified
organization IDs.

### Example 4: Export organizations by name

```powershell
Export-Action1OrganizationsJson `
    -Path 'C:\Reports\AccountingOrganizations.json' `
    -OrgNames 'Accounting'
```

Exports only organizations whose `name` value matches one of the specified
organization names.

### Example 5: Export to a read-only or hidden JSON file

```powershell
Export-Action1OrganizationsJson -Path 'C:\Reports\Organizations.json' -Force
```

Exports organizations and attempts to write to the target file even when file
attributes, such as read-only or hidden, would otherwise prevent writing.

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

### -OrgIds

Specifies one or more organization IDs to export.

Each value must use the standard GUID format, such as
`88c8b425-871e-4ff6-9afc-00df8592c6db`.

```yaml
Type: String[]
Parameter Sets: ByOrgIds
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OrgNames

Specifies one or more organization names to export.

Name matching is case-insensitive. Empty or whitespace-only values are ignored.

```yaml
Type: String[]
Parameter Sets: ByOrgNames
Aliases:

Required: False
Position: Named
Default value: None
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
in the current location using the `Action1_Organizations_yyMMdd_HHmm.json`
naming format.

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

Requires permission to view enterprise settings and organizations in Action1.

## RELATED LINKS

[Get-Action1Organizations](Get-Action1Organizations.md)
[Get-Action1Organization](Get-Action1Organization.md)
[Get-Action1EnterpriseId](../enterprise/Get-Action1EnterpriseId.md)
[Get-Action1Enterprise](../enterprise/Get-Action1Enterprise.md)
[Export-Action1OrganizationsCsv](Export-Action1OrganizationsCsv.md)
[Import-Action1OrganizationsCsv](Import-Action1OrganizationsCsv.md)
[New-Action1Organization](New-Action1Organization.md)
[Update-Action1Organization](Update-Action1Organization.md)
[Remove-Action1Organization](Remove-Action1Organization.md)
