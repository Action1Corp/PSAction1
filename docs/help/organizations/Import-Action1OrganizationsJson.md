---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Import-Action1OrganizationsJson

## SYNOPSIS

Imports Action1 organizations from a JSON file and writes a source-to-target
organization map.

## SYNTAX

```
Import-Action1OrganizationsJson [-Path] <String> [-MapPath <String>] [-ConflictAction <String>] [-Force]
 [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

`Import-Action1OrganizationsJson` reads an organization source JSON file
exported from another Action1 region or enterprise, creates or merges
organizations in the currently configured Action1 target session, and writes a
migration map JSON file.

Run this command after configuring PSAction1 for the target region and target
credentials with `Set-Action1Region` and `Set-Action1Credentials`.

The source JSON file is expected to use the `PSAction1.Organization.v1` schema
written by `Export-Action1OrganizationsJson`. That exporter writes these
top-level properties:

* `schema`
* `datetime`
* `region`
* `enterprise_id`
* `type`
* `items`

Each source item must contain these properties:

* `id`
* `type`
* `self`
* `name`
* `description`
* `enterprise_id`

The map JSON file uses the `PSAction1.OrganizationMigrationMap.v1` schema. The
command validates an existing map file before retrying or updating it. The map
contains these top-level properties:

* `schema`
* `datetime`
* `type`
* `source`
* `target`
* `items`

The **source** and **target** objects contain `region` and `enterprise_id`. The
**items** object is keyed by source organization ID. Each item contains:

* `id`
* `name`
* `description`
* `status`
* `imported_at`

The **imported_at** and top-level **datetime** values are written as UTC
timestamps in the `yyyy-MM-dd'T'HH:mm:ss'Z'` format.

The **status** value is one of:

* `Created`
* `Updated`
* `Skipped`
* `Failed`

If **MapPath** points to an existing map file, the command validates and reads
that map before importing. Items that already contain **id** are not imported
again. Items with a null **id** and **status** set to `Skipped` or `Failed` are
retried and updated in the existing map.

When a target organization with the same name already exists, **ConflictAction**
controls the behavior. The default is `MergeExisting`.

This command prompts for confirmation before creating a target organization and
before merging a source organization into an existing target organization. Use
**Force** to run those actions without confirmation prompts.

## EXAMPLES

### Example 1: Import organizations and create the default map file

```powershell
Import-Action1OrganizationsJson `
    -Path 'D:\Action1\Migration\OrgA\organization.source.json'
```

Imports organizations from the source JSON file. If a target organization with
the same name already exists, the command updates that target organization. The
command creates a map file in the current location using the
`Action1_Organizations_map_yyMMdd_HHmm.json` naming format.

### Example 2: Import organizations and write a specific map file

```powershell
Import-Action1OrganizationsJson `
    -Path 'D:\Action1\Migration\OrgA\organization.source.json' `
    -MapPath 'D:\Action1\Migration\OrgA\organization.map.json'
```

Imports organizations and writes the source-to-target organization mapping to
the specified map JSON file.

### Example 3: Merge an existing target organization by name

```powershell
Import-Action1OrganizationsJson `
    -Path 'D:\Action1\Migration\OrgA\organization.source.json' `
    -MapPath 'D:\Action1\Migration\OrgA\organization.map.json' `
    -ConflictAction MergeExisting
```

When a target organization with the same name exists, the command updates the
existing target organization and records status `Updated` in the map file. If
multiple target organizations have the same name, the item is marked `Failed`.

### Example 4: Create a duplicate target organization name

```powershell
Import-Action1OrganizationsJson `
    -Path 'D:\Action1\Migration\OrgA\organization.source.json' `
    -MapPath 'D:\Action1\Migration\OrgA\organization.map.json' `
    -ConflictAction Duplicate
```

Creates a new target organization even when a target organization with the same
name already exists.

### Example 5: Skip existing target organization names

```powershell
Import-Action1OrganizationsJson `
    -Path 'D:\Action1\Migration\OrgA\organization.source.json' `
    -MapPath 'D:\Action1\Migration\OrgA\organization.map.json' `
    -ConflictAction SkipExisting
```

Creates no new organization when a target organization with the same name
exists and records status `Skipped` in the map file.

### Example 6: Retry previously skipped or failed items

```powershell
Import-Action1OrganizationsJson `
    -Path 'D:\Action1\Migration\OrgA\organization.source.json' `
    -MapPath 'D:\Action1\Migration\OrgA\organization.map.json'
```

Reads the existing map file and retries only source items where **id** is null
and **status** is `Skipped` or `Failed`.

### Example 7: Preview organization import

```powershell
Import-Action1OrganizationsJson `
    -Path 'D:\Action1\Migration\OrgA\organization.source.json' `
    -MapPath 'D:\Action1\Migration\OrgA\organization.map.json' `
    -ConflictAction Duplicate `
    -WhatIf
```

Shows which organizations would be created or updated without making target
organization changes or writing the map file.

### Example 8: Import organizations without confirmation prompts

```powershell
Import-Action1OrganizationsJson `
    -Path 'D:\Action1\Migration\OrgA\organization.source.json' `
    -MapPath 'D:\Action1\Migration\OrgA\organization.map.json' `
    -Force
```

Creates or updates target organizations and writes organization mappings
without prompting for confirmation.

## PARAMETERS

### -Confirm

Controls the standard PowerShell confirmation prompt for creating a target
organization or merging into an existing target organization.

This command has high confirmation impact and prompts by default for those
actions. Use **Force** to run without confirmation prompts.

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

### -ConflictAction

Specifies how the command handles a target organization with the same name as
the source organization.

Valid values are:

* `Duplicate` - Creates a new target organization with the same name.
* `MergeExisting` - Updates the existing target organization.
* `SkipExisting` - Creates nothing and records the source organization as skipped.

The default value is `MergeExisting`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:
Accepted values: Duplicate, MergeExisting, SkipExisting

Required: False
Position: Named
Default value: MergeExisting
Accept pipeline input: False
Accept wildcard characters: False
```

### -Force

Bypasses confirmation prompts for target organization creation and organization
merge actions.

This parameter does not bypass **WhatIf**. When **WhatIf** is specified, the
command previews the action and does not create organizations, update
organizations, or write map items.

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

### -MapPath

Specifies the path to the organization migration map JSON file.

If the path contains a directory that does not exist, the command creates the
directory. If the file already exists, the command validates and updates it.

If this parameter is not specified, the command creates a timestamped map file
in the current location using the `Action1_Organizations_map_yyMMdd_HHmm.json`
naming format.

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

### -Path

Specifies the path to the source organization JSON file to import.

The source file must exist and contain a JSON object with organization items in
the exporter shape described in the command description. Source content is not
pre-validated as a separate schema step; malformed content stops the import
when the command reads or uses the affected value.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIf

Shows what would happen if the command runs. The command does not create target
organizations, update target organizations, or write the map file.

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

### System.Management.Automation.PSCustomObject

Returns one result object for each source organization item. The result object
contains **source_id**, the map item fields, and a **message** property with
row-specific details.

## NOTES

Requires permission to view, create, and update organizations in the target
Action1 enterprise.

Use the generated organization map as input for later organization-scoped object
migration steps, such as endpoint groups, automations, policies, and scripts.

## RELATED LINKS

[Export-Action1OrganizationsJson](Export-Action1OrganizationsJson.md)
[Import-Action1OrganizationsCsv](Import-Action1OrganizationsCsv.md)
[Get-Action1Organizations](Get-Action1Organizations.md)
[New-Action1Organization](New-Action1Organization.md)
[Update-Action1Organization](Update-Action1Organization.md)
[Set-Action1Credentials](../configuration/Set-Action1Credentials.md)
[Set-Action1Region](../configuration/Set-Action1Region.md)
