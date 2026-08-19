---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1UserRoles

## SYNOPSIS

Gets Action1 roles assigned to one user.

## SYNTAX

```
Get-Action1UserRoles [-UserId] <String> [<CommonParameters>]
```

## DESCRIPTION

`Get-Action1UserRoles` validates the supplied user ID as a GUID and calls the
Action1 user roles API endpoint.

The requested GET endpoint is `/users/:userId/roles`. The command uses the
module paging helper and returns the role objects from Action1 without reshaping
them.

## EXAMPLES

### Example 1: Get roles for a user

```powershell
Get-Action1UserRoles -UserId '5e79941d-e4cc-40f3-899b-0cff63836d46'
```

Gets roles assigned to the specified user.

### Example 2: Select role fields

```powershell
Get-Action1UserRoles -UserId '5e79941d-e4cc-40f3-899b-0cff63836d46' |
    Select-Object id, name
```

Gets roles for the user and selects common role identity fields when those
properties are present in the API response.

## PARAMETERS

### -UserId

Specifies the ID of the Action1 user whose roles are retrieved.

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

Returns user role objects from Action1.

## NOTES

The command retrieves paged role results from the Action1 API. Action1 returns
an API error when the user ID does not identify an accessible user.

## RELATED LINKS

[Get-Action1User](Get-Action1User.md)
[Get-Action1Users](Get-Action1Users.md)
