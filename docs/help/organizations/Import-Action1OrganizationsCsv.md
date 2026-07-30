---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Import-Action1OrganizationsCsv

## SYNOPSIS

Imports Action1 organizations from a CSV file and writes a source-to-target
organization map.

## SYNTAX

```
Import-Action1OrganizationsCsv [-Path] <String> [-MapPath <String>] [-ConflictAction <String>] [-Force]
 [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

`Import-Action1OrganizationsCsv` reads an organization source CSV file exported
from another Action1 region or enterprise, creates or matches organizations in
the currently configured Action1 target session, and writes a migration map CSV.

Run this command after configuring PSAction1 for the target region and target
credentials with `Set-Action1Region` and `Set-Action1Credentials`.

The source CSV file must contain these columns:

* `Id`
* `Name`
* `Description`
* `EntityType`
* `EnterpriseId`
* `Region`
* `ExportedAt`

The map CSV file contains these columns:

* `EntityType`
* `SourceId`
* `SourceName`
* `SourceRegion`
* `SourceEnterpriseId`
* `TargetRegion`
* `TargetEnterpriseId`
* `TargetId`
* `TargetName`
* `Status`
* `ImportedAt`

The **Status** value is one of:

* `Created`
* `MatchedExisting`
* `Skipped`
* `Failed`

If **MapPath** points to an existing map file, the command validates and reads
that map before importing. Rows that already contain **TargetId** are not
imported again. Rows with an empty **TargetId** and **Status** set to `Skipped`
or `Failed` are retried and updated in the existing map.

When a target organization with the same name already exists, **ConflictAction**
controls the behavior. The default is `Skip`.

This command prompts for confirmation before creating a target organization and
before recording a source-to-existing-target organization mapping. Use **Force**
to run those actions without confirmation prompts.

## EXAMPLES

### Example 1: Import organizations and create the default map file

```powershell
Import-Action1OrganizationsCsv `
    -Path 'D:\Action1\Migration\OrgA\organization.source.csv'
```

Imports organizations from the source CSV file. If a target organization with
the same name already exists, the source organization is skipped. The command
creates a map file in the current location using the
`Action1_Organizations_map_yyMMdd_HHmm.csv` naming format.

### Example 2: Import organizations and write a specific map file

```powershell
Import-Action1OrganizationsCsv `
    -Path 'D:\Action1\Migration\OrgA\organization.source.csv' `
    -MapPath 'D:\Action1\Migration\OrgA\organization.map.csv'
```

Imports organizations and writes the source-to-target organization mapping to
the specified map CSV file.

### Example 3: Match an existing target organization by name

```powershell
Import-Action1OrganizationsCsv `
    -Path 'D:\Action1\Migration\OrgA\organization.source.csv' `
    -MapPath 'D:\Action1\Migration\OrgA\organization.map.csv' `
    -ConflictAction MatchExisting
```

When a target organization with the same name exists, the command creates no new
organization and records the existing target organization ID in the map file.
If multiple target organizations have the same name, the row is marked `Failed`.

### Example 4: Create a duplicate target organization name

```powershell
Import-Action1OrganizationsCsv `
    -Path 'D:\Action1\Migration\OrgA\organization.source.csv' `
    -MapPath 'D:\Action1\Migration\OrgA\organization.map.csv' `
    -ConflictAction CreateNew
```

Creates a new target organization even when a target organization with the same
name already exists.

### Example 5: Retry previously skipped or failed rows

```powershell
Import-Action1OrganizationsCsv `
    -Path 'D:\Action1\Migration\OrgA\organization.source.csv' `
    -MapPath 'D:\Action1\Migration\OrgA\organization.map.csv' `
    -ConflictAction MatchExisting
```

Reads the existing map file and retries only source rows where **TargetId** is
empty and **Status** is `Skipped` or `Failed`.

### Example 6: Preview organization creation

```powershell
Import-Action1OrganizationsCsv `
    -Path 'D:\Action1\Migration\OrgA\organization.source.csv' `
    -MapPath 'D:\Action1\Migration\OrgA\organization.map.csv' `
    -ConflictAction CreateNew `
    -WhatIf
```

Shows which organizations would be created without creating target organizations
or writing the map file.

### Example 7: Import organizations without confirmation prompts

```powershell
Import-Action1OrganizationsCsv `
    -Path 'D:\Action1\Migration\OrgA\organization.source.csv' `
    -MapPath 'D:\Action1\Migration\OrgA\organization.map.csv' `
    -ConflictAction CreateNew `
    -Force
```

Creates target organizations and writes organization mappings without prompting
for confirmation.

## PARAMETERS

### -Confirm

Controls the standard PowerShell confirmation prompt for creating a target
organization or recording a source-to-existing-target organization mapping.

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

* `CreateNew` - Creates a new target organization with the same name.
* `MatchExisting` - Creates nothing and maps to the existing target organization.
* `Skip` - Creates nothing and records the source organization as skipped.

The default value is `Skip`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:
Accepted values: CreateNew, MatchExisting, Skip

Required: False
Position: Named
Default value: Skip
Accept pipeline input: False
Accept wildcard characters: False
```

### -Force

Bypasses confirmation prompts for target organization creation and organization
mapping actions.

This parameter does not bypass **WhatIf**. When **WhatIf** is specified, the
command previews the action and does not create organizations or write map rows.

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

Specifies the path to the organization migration map CSV file.

If the path contains a directory that does not exist, the command creates the
directory. If the file already exists, the command validates and updates it.

If this parameter is not specified, the command creates a timestamped map file
in the current location using the `Action1_Organizations_map_yyMMdd_HHmm.csv`
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

Specifies the path to the source organization CSV file to import.

The source file must exist and must contain the required source columns described
in the command description. The command stops before making Action1 API changes
when the source file is missing required columns, contains no organization rows,
contains duplicate **Id** values, or contains malformed source organization IDs.

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
organizations or write the map file.

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

Returns one result object for each source organization row. The result object
contains the map fields plus a **Message** property with row-specific details.

## NOTES

Requires permission to view and create organizations in the target Action1
enterprise.

Use the generated organization map as input for later organization-scoped object
migration steps, such as endpoint groups, automations, policies, and scripts.

## RELATED LINKS

[Export-Action1OrganizationsCsv](Export-Action1OrganizationsCsv.md)
[Get-Action1Organizations](../configuration/Get-Action1Organizations.md)
[New-Action1Organization](New-Action1Organization.md)
[Set-Action1Credentials](../configuration/Set-Action1Credentials.md)
[Set-Action1Region](../configuration/Set-Action1Region.md)
