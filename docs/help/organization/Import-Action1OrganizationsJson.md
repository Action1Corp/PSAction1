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
Import-Action1OrganizationsJson [-Path] <String> [-MapPath <String>] [-Force] [-WhatIf] [-Confirm]
 [<CommonParameters>]
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

When a source organization ID already exists as a top-level property in the map,
the command skips that source item. Otherwise, it creates the organization with
`New-Action1Organization`, appends the full created target organization response
to the map under the source organization ID, and saves the map file.

The map file **source_region** and **source_enterprise_id** must match the
source JSON file being imported. The **target_region** and
**target_enterprise_id** values must match the current target region and
enterprise. This prevents appending target objects to a map for a different
source export, tenant, or region. If the mapping header is wrong, the import
stops before processing source items.

The command prompts for confirmation before creating each organization. Use
**WhatIf** to preview organization creation without sending API requests or
writing the map file. Use **Force** to bypass confirmation prompts.

At the end of the import, the command returns a statistics object with source
path, map path, processed count, skipped count, created count, failed count,
source region, target region, and target enterprise ID.

## EXAMPLES

### Example 1: Import organizations and create the default map

```powershell
Import-Action1OrganizationsJson -Path 'C:\Migration\Organizations.json'
```

Imports all unmapped organizations from the export file. The command creates or
reuses a migration map in the current location.

### Example 2: Import organizations with a specific map

```powershell
Import-Action1OrganizationsJson `
    -Path 'C:\Migration\Organizations.json' `
    -MapPath 'C:\Migration\Action1_MigrationMapping_source_target.json'
```

Imports unmapped organizations and stores created target objects in the
specified migration map.

### Example 3: Preview an import

```powershell
Import-Action1OrganizationsJson `
    -Path 'C:\Migration\Organizations.json' `
    -MapPath 'C:\Migration\Action1_MigrationMapping_source_target.json' `
    -WhatIf
```

Shows which organizations would be created. The command does not send API
requests and does not write the migration map.

### Example 4: Import without confirmation prompts

```powershell
Import-Action1OrganizationsJson `
    -Path 'C:\Migration\Organizations.json' `
    -MapPath 'C:\Migration\Action1_MigrationMapping_source_target.json' `
    -Force
```

Imports unmapped organizations without confirmation prompts.

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

### -MapPath

Specifies the JSON migration map path.

If the path exists, the command validates the map schema, source region, source
enterprise ID, target region, and target enterprise ID before processing source
items. If the path does not exist, the command creates a new map with the
`PSAction1.Mapping.v1` header.

If this parameter is omitted, the command creates or reuses a map file in the
current location named
`Action1_MigrationMapping_<source-enterprise-id>_<target-enterprise-id>.json`.

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

Returns a statistics object describing the import.

## NOTES

Requires permission to view enterprise settings and create organizations in
Action1.

## RELATED LINKS

[Export-Action1OrganizationsJson](Export-Action1OrganizationsJson.md)
[New-Action1Organization](New-Action1Organization.md)
[Get-Action1Organizations](Get-Action1Organizations.md)
[Get-Action1EnterpriseId](../enterprise/Get-Action1EnterpriseId.md)
[Get-Action1Region](../configuration/Get-Action1Region.md)
