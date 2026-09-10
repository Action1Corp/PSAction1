---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Import-Action1OrganizationsJson

## SYNOPSIS

Imports organizations from a PSAction1 organization JSON export.

## SYNTAX

```
Import-Action1OrganizationsJson [-Path] <String> [-MapPath <String>] [-MapIndexPath <String>] [-Force]
 [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

`Import-Action1OrganizationsJson` reads a JSON file created by
`Export-Action1OrganizationsJson`, creates each unmapped organization in the
current Action1 target enterprise, and records created target objects in a JSON
migration map.

The source JSON file must contain these top-level properties:

* `schema`
* `datetime`
* `region`
* `enterprise_id`
* `type`
* `items`

The **schema** value must be `PSAction1.Organization.v1`, and the **type** value
must be `Organization`.

The migration map uses schema `PSAction1.Mapping.v1` and contains these header
properties:

* `schema`
* `datetime`
* `source_region`
* `source_enterprise_id`
* `target_region`
* `target_enterprise_id`

Additional top-level properties are source organization IDs. Each source ID maps
to the complete response object returned by `New-Action1Organization` when the
corresponding organization was created in the current target enterprise.

If **MapPath** is not specified, the command creates or reuses a map file in the
current location named
`Action1_MigrationMapping_<source-enterprise-id>_<target-enterprise-id>.json`.

Supported map and index path combinations are:

* **Path** only: use the default map path and rebuild the default index file
  from that map path. If the derived index file already exists, it is replaced.
* **Path** with **MapPath**: use the specified map path and derive the default
  index path from that map path, then rebuild that index file. If the derived
  index file already exists, it is replaced.
* **Path** with **MapPath** and **MapIndexPath**: use both specified paths. If
  the specified index file exists, validate and use it. If it does not exist,
  create it from the migration map or create a header-only index for a new map.
* **Path** with **MapIndexPath** but without **MapPath**: not supported.

When a source organization ID already exists as a top-level property in the map,
the command skips that source item. Otherwise, it creates the organization with
`New-Action1Organization` and records the full created target organization
response under the source organization ID.

When **MapIndexPath** is omitted, the command derives the text index path from
**MapPath** by replacing the map file extension with `.index.txt`, rebuilds the
index from the JSON migration map, and saves the rebuilt index file before
processing source items. If the derived index file already exists, the command
replaces it. If the migration map is new, the command creates a new index
header.

When **MapIndexPath** is specified, **MapPath** must also be specified. If the
specified index exists, the command reads the text index header and source IDs
instead of rebuilding the skip list from the JSON map. If the specified index
does not exist, the command builds it from the migration map when the map
exists, or creates a new index header when the map is new. The index starts
with these header lines:

* `# schema=PSAction1.MappingIndex.v1`
* `# source_region=<source-region>`
* `# source_enterprise_id=<source-enterprise-id>`
* `# target_region=<target-region>`
* `# target_enterprise_id=<target-enterprise-id>`
* `# end_header`

Each following nonblank line contains `<source-id><TAB><target-id>`, where
`<TAB>` is one actual tab character. The target ID is the created response
object's `id` field, or the stored mapped object's `id` when rebuilding the
index. The full response remains in the authoritative JSON map. Skip checks
use only the source ID column.

Both IDs must be nonempty and cannot contain tabs or line breaks. Malformed
rows and conflicting target IDs for the same source ID are rejected. If a
created response cannot supply a valid index ID, the import reports a failure
and retains the response in the JSON map being written, without adding an
index row. Review that mapping before retrying; an index rebuild also fails
when a mapped object cannot supply a valid target ID.

The unreleased schema remains `PSAction1.MappingIndex.v1`. Earlier development
indexes containing only source IDs are not accepted as supplied indexes. Omit
**MapIndexPath** to rebuild the derived index from the JSON map in the new
format, or specify a new index path to rebuild at that location.

The command validates a specified existing index header against the current
source and target migration metadata. It does not verify that a specified
existing index body exactly matches the full JSON map. If the specified index
is stale, objects can be skipped or duplicated.

The command writes changes to a temporary file named
`<MapPath>.inprogress`. After processing completes, it validates that temporary
map and replaces **MapPath** with it. If the command stops before completion,
the original map remains the last completed map and the temporary file is left
for inspection.

The map file **source_region** and **source_enterprise_id** must match the
source JSON file being imported. The **target_region** and
**target_enterprise_id** values must match the current target region and
enterprise. This prevents appending target objects to a map for a different
source export, tenant, or region. If the mapping header is wrong, the import
stops before processing source items.

The command prompts for confirmation before creating each organization. Use
**WhatIf** to preview organization creation without sending API requests or
writing the map or index files. Use **Force** to bypass confirmation prompts.
If you answer **No** or **No to All** at the confirmation prompt, the declined
source items are counted as skipped.

At the end of the import, the command returns a statistics object with source
file path, map file path, map index file path, processed count, skipped count,
created count, failed count, source region, target region, and target
enterprise ID.

## EXAMPLES

### Example 1: Import with default map and default index paths

```powershell
Import-Action1OrganizationsJson -Path 'C:\Migration\Organizations.json'
```

Imports all unmapped organizations from the export file. The command creates or
reuses the default migration map in the current location and rebuilds the
derived default index file from the migration map. If the derived index file
already exists, it is replaced.

### Example 2: Import with a specific map and derived index path

```powershell
Import-Action1OrganizationsJson `
    -Path 'C:\Migration\Organizations.json' `
    -MapPath 'C:\Migration\Action1_MigrationMapping_source_target.json'
```

Imports unmapped organizations and stores created target objects in the
specified migration map. Because **MapIndexPath** is omitted, the command uses
`C:\Migration\Action1_MigrationMapping_source_target.index.txt` as the index
path.

The command rebuilds the derived index file from the specified map before
processing source items.

### Example 3: Import with a specific map and an existing specified index

```powershell
Import-Action1OrganizationsJson `
    -Path 'C:\Migration\Organizations.json' `
    -MapPath 'C:\Migration\Action1_MigrationMapping_source_target.json' `
    -MapIndexPath 'D:\Indexes\Action1_MigrationMapping_source_target.index.txt'
```

Imports unmapped organizations using the specified JSON map and specified text
index. If the specified index exists, the command validates its header and uses
the source IDs in that index for skip checks. The specified index is not rebuilt
from the JSON map.

### Example 4: Import with a specific map and a new specified index

```powershell
Import-Action1OrganizationsJson `
    -Path 'C:\Migration\Organizations.json' `
    -MapPath 'C:\Migration\Action1_MigrationMapping_source_target.json' `
    -MapIndexPath 'D:\Indexes\NewOrganizations.index.txt'
```

Imports unmapped organizations using the specified JSON map and specified text
index path. If `D:\Indexes\NewOrganizations.index.txt` does not exist, the
command creates it from the migration map before processing source items. If
the migration map is new, the command creates a header-only index and appends
source and target ID pairs after successful creates.

### Example 5: Show the unsupported index-only combination

```powershell
Import-Action1OrganizationsJson `
    -Path 'C:\Migration\Organizations.json' `
    -MapIndexPath 'C:\Migration\Action1_MigrationMapping_source_target.index.txt'
```

This command fails before reading tenant context because **MapIndexPath** cannot
be used without **MapPath**.

### Example 6: Preview an import without writing files

```powershell
Import-Action1OrganizationsJson `
    -Path 'C:\Migration\Organizations.json' `
    -MapPath 'C:\Migration\Action1_MigrationMapping_source_target.json' `
    -WhatIf
```

Shows which organizations would be created. The command reads and validates the
source file and resolves target metadata, but it does not send create requests
and does not write the map or index files. **WhatIf** previews are not counted
as confirmation skips.

### Example 7: Import without confirmation prompts

```powershell
Import-Action1OrganizationsJson `
    -Path 'C:\Migration\Organizations.json' `
    -MapPath 'C:\Migration\Action1_MigrationMapping_source_target.json' `
    -Force
```

Imports unmapped organizations without confirmation prompts. The command still
creates or updates the map and index files, and **WhatIf** is still honored when
it is specified.

## PARAMETERS

### -Confirm

Prompts you for confirmation before creating each organization.

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

### -Force

Bypasses confirmation prompts. **WhatIf** is still honored when it is specified.

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

### -MapIndexPath

Specifies an optional text index path containing tab-separated source and target IDs.

When this parameter is specified, **MapPath** must also be specified. The
command validates the index header and uses the index body for source ID skip
checks. The command does not rebuild or fully verify the index against the JSON
map. A stale index can cause unmapped source objects to be skipped or previously
created target objects to be duplicated.

When this parameter is omitted, the command derives the index path from
**MapPath** by replacing the map file extension with `.index.txt`, rebuilds the
index from the JSON migration map, and saves the rebuilt index file before
processing source items. If the derived index file already exists, the command
replaces it. If the migration map is new, the command creates the index header
before importing.

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

### -MapPath

Specifies the JSON migration map path.

If the path exists, the command validates the map schema, source region, source
enterprise ID, target region, and target enterprise ID before processing source
items. If the path does not exist, the command creates a new map with the
`PSAction1.Mapping.v1` header.

If this parameter is omitted, the command creates or reuses a map file in the
current location named
`Action1_MigrationMapping_<source-enterprise-id>_<target-enterprise-id>.json`.

When **MapIndexPath** is omitted, this map path is also used to derive the
default `.index.txt` path. That derived index file is rebuilt from the JSON map
and replaced when it already exists.

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

Specifies the source JSON file created by `Export-Action1OrganizationsJson`.

The file must use schema `PSAction1.Organization.v1`, type `Organization`, and
include the `items` array.

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

Shows what would happen if the command runs. The command is not run.

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

Returns a statistics object describing the import. The object includes
`SourceFile`, `MapFile`, `MapIndexFile`, `Processed`, `Skipped`, `Created`,
`Failed`, `SourceRegion`, `TargetRegion`, and `EnterpriseId`. `Skipped`
includes source items already present in the mapping index or JSON map, and
source items declined at the confirmation prompt in a real run.

## NOTES

Requires permission to view enterprise settings and create organizations in
Action1.

## RELATED LINKS

[Export-Action1OrganizationsJson](Export-Action1OrganizationsJson.md)
[New-Action1Organization](New-Action1Organization.md)
[Get-Action1Organizations](Get-Action1Organizations.md)
[Get-Action1EnterpriseId](../enterprise/Get-Action1EnterpriseId.md)
[Get-Action1Region](../configuration/Get-Action1Region.md)
