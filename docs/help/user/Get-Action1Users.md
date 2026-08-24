---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1Users

## SYNOPSIS

Gets Action1 users available to the current account.

## SYNTAX

### AllUsers (Default)
```
Get-Action1Users [-Limit <Int32>] [<CommonParameters>]
```

### AsPage
```
Get-Action1Users [-AsPage] [-Limit <Int32>] [<CommonParameters>]
```

## DESCRIPTION

`Get-Action1Users` calls the Action1 users API and returns enabled user records
visible to the current credentials.

The requested GET endpoint is `/users`. The command uses the module paging
helper and returns the enabled user objects from Action1 without reshaping them.
Disabled users are not included. To retrieve a disabled user, call
`Get-Action1User` with the user's ID.

Use **AsPage** to return page envelopes that contain an **Items** array and
page metadata. This mode is intended for paged export workflows.

Use **Limit** to control how many users are requested per API page. The value
must be from 1 through the module paging maximum.

## EXAMPLES

### Example 1: List users

```powershell
Get-Action1Users
```

Gets enabled user records available to the current account.

### Example 2: Select user fields

```powershell
Get-Action1Users | Select-Object id, name, email
```

Gets enabled users and selects common identity fields when those properties are
present in the API response.

## PARAMETERS

### -AsPage

Returns page envelope objects instead of writing each user object directly to
the pipeline. Each page contains **Items**, **PageNumber**, **From**, **Limit**,
**TotalItems**, and **NextPage** properties.

```yaml
Type: SwitchParameter
Parameter Sets: AsPage
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Limit

Specifies the maximum number of users to request per API page.

The value must be from 1 through the module paging maximum.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 200
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe input to this command.

## OUTPUTS

### System.Object

Returns enabled user objects from Action1. With **AsPage**, returns page
envelope objects containing enabled user objects and page metadata.

## NOTES

The command retrieves paged enabled-user results from the Action1 API. Disabled
users are available only through `Get-Action1User` by user ID.

## RELATED LINKS

[Get-Action1User](Get-Action1User.md)
[Get-Action1UserRoles](Get-Action1UserRoles.md)
[New-Action1User](New-Action1User.md)
[Update-Action1User](Update-Action1User.md)
[Remove-Action1User](Remove-Action1User.md)
[Export-Action1UsersJson](Export-Action1UsersJson.md)
[Set-Action1Credentials](../configuration/Set-Action1Credentials.md)
[Get-Action1Enterprise](../enterprise/Get-Action1Enterprise.md)
