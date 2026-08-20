---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1User

## SYNOPSIS

Gets one Action1 user by user ID.

## SYNTAX

```
Get-Action1User [-UserId] <String> [<CommonParameters>]
```

## DESCRIPTION

`Get-Action1User` validates the supplied user ID as a GUID and calls the
single-user Action1 API endpoint.

The requested GET endpoint is `/users/:userId`. This command calls the
single-user endpoint without pagination and returns the user object from Action1
without reshaping it.

## EXAMPLES

### Example 1: Get a user by ID

```powershell
Get-Action1User -UserId '5e79941d-e4cc-40f3-899b-0cff63836d46'
```

Gets the user with the specified ID.

### Example 2: Display user details

```powershell
Get-Action1User -UserId '5e79941d-e4cc-40f3-899b-0cff63836d46' |
    Format-List
```

Gets the user and displays all returned fields.

## PARAMETERS

### -UserId

Specifies the ID of the Action1 user to retrieve.

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

### System.Object

Returns the user object returned by Action1.

## NOTES

The command calls the single-user API path without pagination. Action1 returns
an API error when the user ID does not identify an accessible user.

## RELATED LINKS

[Get-Action1Users](Get-Action1Users.md)
[Get-Action1UserRoles](Get-Action1UserRoles.md)
[Update-Action1User](Update-Action1User.md)
[Remove-Action1User](Remove-Action1User.md)
[Export-Action1UsersJson](Export-Action1UsersJson.md)
[Set-Action1Credentials](../configuration/Set-Action1Credentials.md)
