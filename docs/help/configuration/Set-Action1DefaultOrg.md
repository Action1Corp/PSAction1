---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Set-Action1DefaultOrg

## SYNOPSIS

Sets the default Action1 organization for the current PowerShell session.

## SYNTAX

### ById (Default)
```
Set-Action1DefaultOrg [-Org_ID] <String> [<CommonParameters>]
```

### ByName
```
Set-Action1DefaultOrg -Org_Name <String> [<CommonParameters>]
```

## DESCRIPTION

`Set-Action1DefaultOrg` configures the default Action1 organization context used by other commands in the module.

The command supports two ways to set the default organization:

* By organization ID using `-Org_ID`.
* By unique organization name using `-Org_Name`.

When `-Org_ID` is used, the command resolves the organization by ID and stores both the organization ID and organization name as the default organization context.

When `-Org_Name` is used, the command retrieves the available organizations, searches for an organization with the specified name, and stores both the matching organization's ID and name as the default organization context.

The default organization value is stored only for the duration of the current PowerShell session.

## EXAMPLES

### Example 1: Set the default organization by ID

```powershell
PS C:\> Set-Action1DefaultOrg -Org_ID "88c8b425-871e-4ff6-9afc-00df8592c6db"
```

Resolves the organization by ID and sets it as the default organization.

This is the recommended option for automation scripts because organization IDs are unique and unambiguous.

### Example 2: Set the default organization by name

```powershell
PS C:\> Set-Action1DefaultOrg -Org_Name "MyOrgName"
```

Finds an organization named `MyOrgName` and stores its organization ID and name as the default organization context.

The organization name must be unique. If more than one organization has the specified name, the command returns a terminating error and the organization ID must be used instead.

### Example 3: Use the OrgId alias

```powershell
PS C:\> Set-Action1DefaultOrg -OrgId "88c8b425-871e-4ff6-9afc-00df8592c6db"
```

Uses the `OrgId` alias for `-Org_ID`.

### Example 4: Use the OrgName alias

```powershell
PS C:\> Set-Action1DefaultOrg -OrgName "MyOrgName"
```

Uses the `OrgName` alias for `-Org_Name`.

## PARAMETERS

### -Org_ID

Specifies the Action1 organization ID to use as the default organization for subsequent module commands.

The command resolves the ID through the API and stores the matching organization ID and name.

```yaml
Type: String
Parameter Sets: ById
Aliases: OrgId

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Org_Name

Specifies the Action1 organization name to resolve and use as the default organization.

The command searches the available organizations for an exact name match. The name must match exactly and must identify a single organization.

If no organization is found, the command returns a terminating error.

If multiple organizations have the same name, the command returns a terminating error and instructs the user to specify the organization ID with `-Org_ID`.

Using this parameter requires valid Action1 authentication and access to list organizations.

```yaml
Type: String
Parameter Sets: ByName
Aliases: OrgName

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe objects to this command.

## OUTPUTS

### None

This command does not produce output. It sets a module-level default organization value for the current PowerShell session.

## NOTES

The default organization value is stored in a script scope variable and is available only for the lifetime of the current PowerShell session.

`-Org_ID` is the most deterministic option and should be preferred in automation scripts.

`-Org_Name` is provided for convenience in interactive scenarios and scripts where organization names are known to be unique.

## RELATED LINKS

[Set-Action1DefaultOrg](Set-Action1DefaultOrg.md)
[Get-Action1DefaultOrgId](Get-Action1DefaultOrgId.md)
[Get-Action1DefaultOrgName](Get-Action1DefaultOrgName.md)
[Set-Action1Credentials](Set-Action1Credentials.md)
[Set-Action1Region](Set-Action1Region.md)
[about_PSAction1](about_PSAction1.md)
