---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Export-Action1UsersJson

## SYNOPSIS

Exports Action1 users to a JSON file.

## SYNTAX

### AllUsers (Default)
```
Export-Action1UsersJson [[-Path] <String>] [-Force] [<CommonParameters>]
```

### ByUserIds
```
Export-Action1UsersJson [[-Path] <String>] [-UserIds <String[]>] [-Force] [<CommonParameters>]
```

## DESCRIPTION

`Export-Action1UsersJson` calls `Get-Action1Users`, optionally filters the
returned user list by user ID, and exports the selected users to a JSON file.

The command writes a single JSON object with the following top-level
properties:

* `schema`
* `datetime`
* `region`
* `enterprise_id`
* `organization_id`
* `type`
* `items`

The **schema** property is set to `PSAction1.User.v1`. The **datetime**
property contains the UTC export timestamp in the
`yyyy-MM-dd'T'HH:mm:ss'Z'` format. The **region** property is populated from
`Get-Action1Region`. The **enterprise_id** property is populated from
`Get-Action1EnterpriseId`. The **organization_id** property is populated from
`Get-Action1DefaultOrgId`. The **type** property is set to `User`.

The **items** array contains the user objects returned by `Get-Action1Users`.
Item fields are not remapped, so all fields returned by the source command are
preserved in the JSON output.

Use **UserIds** to export only users whose `id` value matches one of the
specified IDs.

The command creates the target directory when it does not already exist and
overwrites the target JSON file if it already exists.

Use **Force** to write to the target file when file attributes, such as
read-only or hidden, would otherwise prevent writing. **Force** does not
override file locks or insufficient file system permissions.

## EXAMPLES

### Example 1: Export all users to the default JSON file

```powershell
Export-Action1UsersJson
```

Exports all users returned by `Get-Action1Users` to a timestamped JSON file in
the current location.

### Example 2: Export all users to a specific file

```powershell
Export-Action1UsersJson -Path 'C:\Reports\Users.json'
```

Exports all users to the specified JSON file.

### Example 3: Export users by ID

```powershell
Export-Action1UsersJson `
    -Path 'C:\Reports\SelectedUsers.json' `
    -UserIds '387a511f-8aac-4ec3-a8f2-47f2869e9500'
```

Exports only users whose `id` value matches one of the specified user IDs.

### Example 4: Export to a read-only or hidden JSON file

```powershell
Export-Action1UsersJson -Path 'C:\Reports\Users.json' -Force
```

Exports users and attempts to write to the target file even when file
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

### -Path

Specifies the path to the JSON file to create.

If the path contains a directory that does not exist, the command creates the
directory. If the file already exists, the command overwrites it.

If the existing target file has read-only or hidden file attributes, use
**Force**.

If this parameter is not specified, the command creates a timestamped JSON file
in the current location using the `Action1_Users_yyMMdd_HHmmssZ.json` naming
format. The `Z` suffix marks the timestamp as UTC.

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

### -UserIds

Specifies one or more user IDs to export.

Each value must use the standard GUID format, such as
`387a511f-8aac-4ec3-a8f2-47f2869e9500`.

```yaml
Type: String[]
Parameter Sets: ByUserIds
Aliases:

Required: False
Position: Named
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

Requires permission to view enterprise settings and users in Action1. The
default Action1 organization must be configured because the export schema
includes the current organization ID.

## RELATED LINKS

[Get-Action1Users](Get-Action1Users.md)
[Get-Action1User](Get-Action1User.md)
[Get-Action1UserRoles](Get-Action1UserRoles.md)
[Remove-Action1User](Remove-Action1User.md)
[Get-Action1EnterpriseId](../enterprise/Get-Action1EnterpriseId.md)
[Get-Action1DefaultOrgId](../configuration/Get-Action1DefaultOrgId.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
