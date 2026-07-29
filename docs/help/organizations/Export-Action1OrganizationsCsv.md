---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Export-Action1OrganizationsCsv

## SYNOPSIS

Exports Action1 organizations to a CSV file.

## SYNTAX

### AllOrganizations (Default)
```
Export-Action1OrganizationsCsv [[-Path] <String>] [-Force] [<CommonParameters>]
```

### ByOrgIds
```
Export-Action1OrganizationsCsv [[-Path] <String>] [-OrgIds <String[]>] [-Force]
 [<CommonParameters>]
```

### ByOrgNames
```
Export-Action1OrganizationsCsv [[-Path] <String>] [-OrgNames <String[]>] [-Force]
 [<CommonParameters>]
```

## DESCRIPTION

`Export-Action1OrganizationsCsv` calls `Get-Action1Organizations`, optionally
filters the returned organization list by organization ID or organization name,
and exports the selected organizations to a CSV file.

The command writes a fixed header row and then appends one CSV row for each
selected organization. The CSV file contains these columns in this order:

* `OrgId`
* `Name`
* `Description`
* `Type`
* `EnterpriseId`
* `Region`
* `ExportedAt`

The **Region** column is populated from `Get-Action1Region`. The
**ExportedAt** column contains the per-organization UTC export timestamp in the
`yyyy-MM-dd_HH-mm-ss` format.

Use either **OrgIds** or **OrgNames** to filter the export. These parameters are
mutually exclusive and cannot be used in the same command.

The command creates the target directory when it does not already exist and
overwrites the target CSV file if it already exists.

Use **Force** to write to the target file when file attributes, such as read-only
or hidden, would otherwise prevent writing. **Force** does not override file
locks or insufficient file system permissions.

## EXAMPLES

### Example 1: Export all organizations to the default CSV file

```powershell
Export-Action1OrganizationsCsv
```

Exports all organizations returned by `Get-Action1Organizations` to a timestamped
CSV file in the current location.

### Example 2: Export all organizations to a specific file

```powershell
Export-Action1OrganizationsCsv -Path 'C:\Reports\Organizations.csv'
```

Exports all organizations to the specified CSV file.

### Example 3: Export organizations by ID

```powershell
Export-Action1OrganizationsCsv `
    -Path 'C:\Reports\SelectedOrganizations.csv' `
    -OrgIds '88c8b425-871e-4ff6-9afc-00df8592c6db'
```

Exports only organizations whose `OrgId` value matches one of the specified
organization IDs.

### Example 4: Export organizations by name

```powershell
Export-Action1OrganizationsCsv `
    -Path 'C:\Reports\AccountingOrganizations.csv' `
    -OrgNames 'Accounting'
```

Exports only organizations whose `Name` value matches one of the specified
organization names.

### Example 5: Export to a read-only or hidden CSV file

```powershell
Export-Action1OrganizationsCsv -Path 'C:\Reports\Organizations.csv' -Force
```

Exports organizations and attempts to write to the target file even when file
attributes, such as read-only or hidden, would otherwise prevent writing.

## PARAMETERS

### -Force

Forces the command to write to the target CSV file when file attributes, such as
read-only or hidden, would otherwise prevent writing.

This parameter does not override file locks or insufficient file system
permissions. Close the file if it is open in another application, such as
Microsoft Excel, and verify that you have write permission to the target
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

Specifies the path to the CSV file to create.

If the path contains a directory that does not exist, the command creates the
directory. If the file already exists, the command overwrites it.

If the existing target file has read-only or hidden file attributes, use
**Force**.

If this parameter is not specified, the command creates a timestamped CSV file
in the current location using the `Action1_Organizations_yyMMdd_HHmm.csv`
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

This command does not return pipeline output. It creates or overwrites a CSV
file at the specified path.

## NOTES

Requires permission to view organizations in Action1.

## RELATED LINKS

[Get-Action1Organizations](../configuration/Get-Action1Organizations.md)
[Get-Action1Organization](Get-Action1Organization.md)
[New-Action1Organization](New-Action1Organization.md)
[Update-Action1Organization](Update-Action1Organization.md)
[Remove-Action1Organization](Remove-Action1Organization.md)
