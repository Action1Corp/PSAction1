---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Remove-Action1User

## SYNOPSIS

Deletes one Action1 user by user ID.

## SYNTAX

```
Remove-Action1User [-UserId] <String> [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

`Remove-Action1User` validates the supplied user ID as a GUID and calls the
single-user Action1 API endpoint with the DELETE method.

The requested DELETE endpoint is `/users/:userId`.

This command supports PowerShell confirmation. Use **-WhatIf** to preview the
delete operation. Use **-Force** to bypass the confirmation prompt.

## EXAMPLES

### Example 1: Delete a user

```powershell
Remove-Action1User -UserId '5e79941d-e4cc-40f3-899b-0cff63836d46'
```

Prompts for confirmation, then deletes the specified user.

### Example 2: Preview user deletion

```powershell
Remove-Action1User -UserId '5e79941d-e4cc-40f3-899b-0cff63836d46' -WhatIf
```

Shows what would be deleted without sending the DELETE request.

### Example 3: Delete without prompting

```powershell
Remove-Action1User -UserId '5e79941d-e4cc-40f3-899b-0cff63836d46' -Force
```

Deletes the user without prompting for confirmation.

## PARAMETERS

### -Confirm

Prompts you for confirmation before running the command.

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

Bypasses the confirmation prompt. **-WhatIf** is still honored when it is specified.

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

### -UserId

Specifies the ID of the Action1 user to delete.

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

### PSCustomObject

Returns a status object with UserId, Status, and Response. The Response value
contains the raw response body returned by the DELETE request. Status can be
Removed, Skipped, or Failed.

## NOTES

Requires permission to manage users in Action1.

## RELATED LINKS

[Get-Action1User](Get-Action1User.md)
[Get-Action1Users](Get-Action1Users.md)
[Get-Action1UserRoles](Get-Action1UserRoles.md)
[Update-Action1User](Update-Action1User.md)
[Export-Action1UsersJson](Export-Action1UsersJson.md)
[Set-Action1Credentials](../configuration/Set-Action1Credentials.md)
