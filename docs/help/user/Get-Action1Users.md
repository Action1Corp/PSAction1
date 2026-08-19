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

```
Get-Action1Users [<CommonParameters>]
```

## DESCRIPTION

`Get-Action1Users` calls the Action1 users API and returns user records visible
to the current credentials.

The requested GET endpoint is `/users`. The command uses the module paging
helper and returns the user objects from Action1 without reshaping them.

## EXAMPLES

### Example 1: List users

```powershell
Get-Action1Users
```

Gets user records available to the current account.

### Example 2: Select user fields

```powershell
Get-Action1Users | Select-Object id, name, email
```

Gets users and selects common identity fields when those properties are present
in the API response.

## PARAMETERS

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe input to this command.

## OUTPUTS

### System.Object

Returns user objects from Action1.

## NOTES

The command retrieves paged results from the Action1 API.

## RELATED LINKS

[Set-Action1Credentials](../configuration/Set-Action1Credentials.md)
[Get-Action1Enterprise](../enterprise/Get-Action1Enterprise.md)
