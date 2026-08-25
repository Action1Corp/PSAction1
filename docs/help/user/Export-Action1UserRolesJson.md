---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Export-Action1UserRolesJson

## SYNOPSIS

Exports Action1 roles assigned to one user to a JSON file.

## SYNTAX

```
Export-Action1UserRolesJson [-UserId] <String> [[-Path] <String>] [-Force] [<CommonParameters>]
```

## DESCRIPTION

`Export-Action1UserRolesJson` calls `Get-Action1UserRoles` for the specified user
ID and exports the returned role list to a JSON file.

The command writes a single JSON object with the following top-level
properties:

* `schema`
* `datetime`
* `region`
* `enterprise_id`
* `organization_id`
* `user_id`
* `type`
* `items`

The **schema** property is set to `PSAction1.Role.v1`. The **datetime**
property contains the UTC export timestamp in the
`yyyy-MM-dd'T'HH:mm:ss'Z'` format. The **region** property is populated from
`Get-Action1Region`. The **enterprise_id** property is populated from
`Get-Action1EnterpriseId`. The **organization_id** property is populated from
`Get-Action1DefaultOrgId`. The **user_id** property is set to the supplied
user ID. The **type** property is set to `Role`.

The **items** array contains the role objects returned by
`Get-Action1UserRoles`. Item fields are not remapped, so all fields returned
by the source command are preserved in the JSON output.

The command creates the target directory when it does not already exist.

If the target JSON file already exists, the command stops before writing. Use
**Force** to overwrite an existing target JSON file.

**Force** also passes through to the underlying file write operation for file
attributes, such as read-only or hidden, that would otherwise prevent writing.
**Force** does not override file locks or insufficient file system permissions.

## EXAMPLES

### Example 1: Export user roles to the default JSON file

```powershell
Export-Action1UserRolesJson -UserId '5e79941d-e4cc-40f3-899b-0cff63836d46'
```

Exports roles assigned to the specified user to a timestamped JSON file in the
current location.

### Example 2: Export user roles to a specific file

```powershell
Export-Action1UserRolesJson `
    -UserId '5e79941d-e4cc-40f3-899b-0cff63836d46' `
    -Path 'C:\Reports\UserRoles.json'
```

Exports roles assigned to the specified user to the specified JSON file.

### Example 3: Overwrite an existing JSON file

```powershell
Export-Action1UserRolesJson `
    -UserId '5e79941d-e4cc-40f3-899b-0cff63836d46' `
    -Path 'C:\Reports\UserRoles.json' `
    -Force
```

Exports user roles and overwrites the target file if it already exists.

## PARAMETERS

### -Force

Forces the command to overwrite the target JSON file when it already exists.

This parameter also passes through to the underlying file write operation for
file attributes, such as read-only or hidden, that would otherwise prevent
writing.

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
directory. If the file already exists, the command stops before writing. Use
**Force** to overwrite an existing file.

If the existing target file has read-only or hidden file attributes, use
**Force**.

If this parameter is not specified, the command creates a timestamped JSON file
in the current location using the
`Action1_UserRoles_UserId_yyMMdd_HHmmssZ.json` naming format. The `Z` suffix
marks the timestamp as UTC.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -UserId

Specifies the ID of the Action1 user whose roles are exported.

The user ID must use the standard GUID format, such as
`5e79941d-e4cc-40f3-899b-0cff63836d46`.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe input to this command.

## OUTPUTS

### None

This command does not return pipeline output. It creates a JSON file at the
specified path.

## NOTES

Requires permission to view enterprise settings, the selected user, and user
roles in Action1. The default Action1 organization must be configured because
the export schema includes the current organization ID.

## RELATED LINKS

[Get-Action1UserRoles](Get-Action1UserRoles.md)
[Get-Action1User](Get-Action1User.md)
[Get-Action1Users](Get-Action1Users.md)
[Export-Action1UsersJson](Export-Action1UsersJson.md)
[Get-Action1EnterpriseId](../enterprise/Get-Action1EnterpriseId.md)
[Get-Action1DefaultOrgId](../configuration/Get-Action1DefaultOrgId.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
