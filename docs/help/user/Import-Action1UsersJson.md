---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Import-Action1UsersJson

## SYNOPSIS

Imports users from a PSAction1 user JSON export.

## SYNTAX

```
Import-Action1UsersJson [-Path] <String> -TemporaryPassword <String> [-MapPath <String>]
 [-MapIndexPath <String>] [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

`Import-Action1UsersJson` reads a file created by `Export-Action1UsersJson`,
creates unmapped users with `New-Action1User` in the current target enterprise,
and records complete created response objects in a JSON migration map.

The source must contain `schema`, `datetime`, `region`, `enterprise_id`,
`organization_id`, `type`, and `items`. The schema must be `PSAction1.User.v1`,
the type must be `User`, and `items` must be an array. The source enterprise ID
and each source user ID must use the standard GUID format.

The importer passes `first_name`, `last_name`, and `email` to `New-Action1User`.
It passes nonblank `phone`, `timezone`, and `enabled` values when available.
Absent, null, or blank optional values are omitted so the create operation uses
its defaults. Exported `session_timeout` values are seconds; the importer
converts them to minutes for `New-Action1User`. A supplied timeout must be an
integer from 300 through 86400 seconds and divisible by 60. Other profile
validation is performed by `New-Action1User`.

The export does not contain passwords. The required **TemporaryPassword**
parameter supplies the same temporary initial password for every created user.
Users are expected to change this temporary password after signing in; the
importer does not enforce a password change. The importer does not add the
temporary password to the migration map or statistics.

Roles, MFA settings, identity provider settings, verification flags, system
flags, user type, and other fields unsupported by `New-Action1User` are not
restored. Both Interactive and API records are attempted through the same
`New-Action1User` operation; API records are not recreated as API credentials.
The source `organization_id` is export metadata; it does not select
a target organization or assign user roles. Existing users can be mapped by
email after the specific already-exists response described below. Their
profiles are not updated or merged with the source record.

The migration map uses schema `PSAction1.Mapping.v1` and these header properties:

* `schema`
* `datetime`
* `source_region`
* `source_enterprise_id`
* `target_region`
* `target_enterprise_id`

Each additional top-level source ID maps to the complete response returned by
`New-Action1User`, or the complete user object recovered from `Get-Action1Users`
after either recognized HTTP 400 create error described below. An already
mapped source ID is skipped. Unmapped source IDs trigger create attempts.
Existing map headers must match the source export and current target region
and enterprise before the command processes any users.

Before each approved create request, the importer reads `Get-Action1Users` and
captures existing user IDs. If creation fails with HTTP 400 and the known
`Lead` / `invalid ID field: undefined` message, it reads the users list again.
Recovery requires exactly one user whose ID was absent before creation and
whose email matches the requested email, ignoring case. List order is not used.
Recovery validates the captured IDs as standard GUIDs and the requested email
using the same format validation as `New-Action1User` before reading the list.

When no match appears immediately, the importer makes up to three post-create
list reads, waiting one second between reads. A recovered user counts as
created: its complete list response is appended under the source ID in the
JSON map, and the source ID is appended to the mapping index. The create
request is never repeated during recovery.

If creation instead returns HTTP 400 with
`This user already exists in this enterprise.`, the importer resolves the
existing user from `Get-Action1Users` by email, ignoring case. Exactly one
distinct user ID must match, and that ID must be a standard GUID. This lookup
includes users that were present before the create request.

The existing user's complete list response is written under the source ID in
the JSON map, and the source ID is appended to the mapping index. This record
increments **Failed**, not **Created** or **Skipped**, because the create
request failed. The handled conflict does not emit another error or stop
processing, even with **ErrorAction** set to `Stop`. On a later run, the mapped
source ID is skipped. If the existing user cannot be resolved uniquely, the
record fails without adding a map or index entry.

Unrelated errors, multiple matching new IDs, and users that do not appear in
the list remain failures and are not mapped. Users hidden from the list,
including disabled users, cannot be recovered by this method. Successful
create responses continue to be mapped directly. **WhatIf** and declined
confirmations skip both the pre-create user list read and the create request.

If **MapPath** is omitted, the map defaults to
`Action1_MigrationMapping_<source-enterprise-id>_<target-enterprise-id>.json`
in the current location. If **MapIndexPath** is omitted, its path is derived by
replacing the map extension with `.index.txt`. The derived index is rebuilt
from the authoritative JSON map on every run, overwriting an existing derived
index. A new map starts with a header-only index.

An explicitly supplied **MapIndexPath** requires **MapPath**. If that index
exists, its header is validated and its source IDs are used for skip checks.
Its body is not compared with the JSON map; the caller must keep it consistent.
A stale supplied index can skip unmapped users or cause duplicate create
attempts. A missing explicit index is built from the map. A nonempty supplied
index without an existing JSON map is rejected.

The index contains these header lines, then one source ID per line:

* `# schema=PSAction1.MappingIndex.v1`
* `# source_region=<source-region>`
* `# source_enterprise_id=<source-enterprise-id>`
* `# target_region=<target-region>`
* `# target_enterprise_id=<target-enterprise-id>`
* `# end_header`

The command writes map changes to `<MapPath>.inprogress`, closes and validates
that JSON, then replaces the final map. An existing temporary map blocks a real
import until it has been reviewed and recovered or removed. If processing stops,
the last completed map remains intact and the temporary map is left for
inspection. A map or index write failure stops the import. Users already created
in Action1 are not rolled back; inspect the temporary map before retrying.

The command prompts before each user creation. **Force** bypasses confirmation
and still honors **WhatIf**. **WhatIf** reads the source and resolves target
metadata, but sends no user create requests and writes no directories, map, or
index. Declined confirmations count as skipped; previews do not.

Invalid source records and unhandled create failures write errors and count as
failed. Processing continues unless **ErrorAction** is `Stop`. Successful
records and resolved already-existing users are saved even when other records
fail during a completed run.

## EXAMPLES

### Example 1: Preview an import

```powershell
Import-Action1UsersJson `
    -Path 'C:\Migration\Users.json' `
    -TemporaryPassword $temporaryPassword `
    -WhatIf
```

Uses a temporary password already supplied in `$temporaryPassword`. Previews user
creation with the default map and derived index paths without writing files.

### Example 2: Import with a specific map

```powershell
Import-Action1UsersJson `
    -Path 'C:\Migration\Users.json' `
    -TemporaryPassword $temporaryPassword `
    -MapPath 'C:\Migration\Users.mapping.json'
```

Prompts before creating each unmapped user. Rebuilds
`C:\Migration\Users.mapping.index.txt` from the map before processing users.
An existing derived index is overwritten. If the map does not exist, the
command starts a new map and a header-only index.
Omit **MapPath** to use the default source/target enterprise map filename.

### Example 3: Use a caller-maintained index

```powershell
Import-Action1UsersJson `
    -Path 'C:\Migration\Users.json' `
    -TemporaryPassword $temporaryPassword `
    -MapPath 'C:\Migration\Users.mapping.json' `
    -MapIndexPath 'C:\Migration\Users.index.txt' `
    -Force
```

Imports without confirmation. Validates an existing explicit index header and
uses its source IDs; creates the index from the map if it does not exist.
The caller must keep an existing explicit index consistent with the JSON map.
**Force** bypasses confirmation; it does not rebuild an existing explicit index.

### Example 4: Import with default map and index paths

```powershell
Import-Action1UsersJson `
    -Path 'C:\Migration\Users.json' `
    -TemporaryPassword $temporaryPassword
```

Omits both **MapPath** and **MapIndexPath**. Creates or reuses
`Action1_MigrationMapping_<source-enterprise-id>_<target-enterprise-id>.json`
in the current location. The index uses the same filename with `.index.txt`
instead of `.json` and is rebuilt from the map on every real run. The default
map location is the current location, which can differ from the source file's
directory. Prompts before each user creation.

### Example 5: Reuse a map with a relative path and rebuild its index

```powershell
Import-Action1UsersJson `
    -Path 'C:\Migration\Users.json' `
    -TemporaryPassword $temporaryPassword `
    -MapPath '.\Mappings\Users.mapping.json' `
    -Force
```

Resolves **MapPath** relative to the current location. When the map exists, its
header is validated and its recorded source IDs are skipped. Because
**MapIndexPath** is omitted, `Mappings\Users.mapping.index.txt` is rebuilt from
the map, replacing an existing derived index. This combination can rebuild a
stale derived index without deleting the authoritative JSON map. **Force**
bypasses user creation confirmation prompts.

### Example 6: Create a missing explicit index in a separate directory

```powershell
Import-Action1UsersJson `
    -Path 'C:\Migration\Users.json' `
    -TemporaryPassword $temporaryPassword `
    -MapPath 'C:\Migration\Users.mapping.json' `
    -MapIndexPath 'D:\MigrationIndexes\Users.index.txt'
```

Uses an explicit map and a separate explicit index path. If the index does not
exist, the command creates its parent directory as needed and builds the index
from the map. If neither file exists, it starts a new map and header-only index.
If the explicit index already exists, its header is validated and its body is
used without rebuilding. A nonempty existing index without a JSON map is
rejected.

### Example 7: Preview with both paths explicitly specified

```powershell
Import-Action1UsersJson `
    -Path 'C:\Migration\Users.json' `
    -TemporaryPassword $temporaryPassword `
    -MapPath 'C:\Migration\Users.mapping.json' `
    -MapIndexPath 'D:\MigrationIndexes\Users.index.txt' `
    -Force `
    -WhatIf
```

Validates the source and any existing map and explicit index, resolves target
metadata, and previews unmapped user creation. It does not create directories,
write either file, or send create requests. **WhatIf** remains effective even
when **Force** is specified. Remove **WhatIf** to import using these paths
without confirmation prompts.

### Example 8: Reject an index path without a map path

```powershell
Import-Action1UsersJson `
    -Path 'C:\Migration\Users.json' `
    -TemporaryPassword $temporaryPassword `
    -MapIndexPath 'D:\MigrationIndexes\Users.index.txt'
```

This unsupported combination fails with
`MapPath is required when MapIndexPath is specified.` before reading the source
file, looking up target metadata, or writing files. Supplying **MapIndexPath**
requires an explicit **MapPath**; the default map path is not used for this
combination.

## PARAMETERS

### -Confirm

Prompts for confirmation before creating each user. The command has high
confirmation impact and prompts by default with the default confirmation
preference. The importer owns confirmation; the nested create command does not
prompt a second time.

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

Bypasses user creation confirmation prompts while still honoring **WhatIf**.

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

Specifies an optional caller-maintained text index. Requires **MapPath**. An
existing explicit index is header-validated and used without rebuilding or
comparing its body with the map. When omitted, the derived `.index.txt` file is
rebuilt from the JSON map on every real run. **WhatIf** does not write the index.

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

Specifies the JSON migration map. Existing maps are validated before processing.
Defaults to `Action1_MigrationMapping_<source-enterprise-id>_<target-enterprise-id>.json`
in the current location. New maps are created only outside **WhatIf**. Source,
map, index, and temporary map paths must be different.

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

Specifies a JSON file created by `Export-Action1UsersJson` with schema
`PSAction1.User.v1`, type `User`, and the export header and `items` array.

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

### -TemporaryPassword

Specifies one temporary initial password shared by all users created during this
import. Users are expected to change it after signing in. This command does not
enforce a password change.
Requires at least 12 characters, a number, an uppercase letter, and a lowercase
letter, matching `New-Action1User`. Required even for **WhatIf**. The parameter
uses a string because `New-Action1User` accepts a string for the API request body.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIf

Previews user creation without create requests or local file writes. Source and
map validation and target metadata lookup still occur.

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

Returns `SourceFile`, `MapFile`, `MapIndexFile`, `Processed`, `Skipped`,
`Created`, `Failed`, `SourceRegion`, `TargetRegion`, and `EnterpriseId`.
`Skipped` includes mapped source IDs and declined confirmations. `Created`
counts newly created users whose responses were recorded in the map and index,
including recovery after the known Lead error. `Failed` includes already-exists
responses that were resolved and mapped, as well as records that failed without
a mapping. A nonzero `Failed` count therefore does not imply that all failed
source IDs are absent from the map.
Terminating errors prevent the final statistics object from being returned.

## NOTES

Requires permission to view enterprise settings, list users, and create users
in the current Action1 target enterprise. Configure the target session before
importing.

## RELATED LINKS

[Export-Action1UsersJson](Export-Action1UsersJson.md)
[New-Action1User](New-Action1User.md)
[Get-Action1Users](Get-Action1Users.md)
[Import-Action1OrganizationsJson](../organization/Import-Action1OrganizationsJson.md)
[Get-Action1EnterpriseId](../enterprise/Get-Action1EnterpriseId.md)
[Get-Action1Region](../configuration/Get-Action1Region.md)
