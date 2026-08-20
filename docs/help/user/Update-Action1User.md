---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Update-Action1User

## SYNOPSIS

Updates one Action1 user by user ID.

## SYNTAX

```
Update-Action1User [-UserId] <String> [-FirstName <String>] [-LastName <String>]
    [-Email <String>] [-Phone <String>] [-Timezone <String>] [-Enabled <String>]
    [-SessionTimeout <Int32>] [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

`Update-Action1User` validates the supplied user ID as a GUID and calls the
single-user Action1 API endpoint with the PATCH method.

The requested PATCH endpoint is `/users/:userId`.

The command sends only fields whose parameters are specified. **-SessionTimeout**
accepts a value in minutes and sends the API `session_timeout` field in seconds.
**-Enabled** accepts `yes` or `no`.

This command supports PowerShell confirmation. Use **-WhatIf** to preview the
update operation. Use **-Force** to bypass the confirmation prompt.

## EXAMPLES

### Example 1: Update a user's profile fields

```powershell
Update-Action1User `
    -UserId '5e79941d-e4cc-40f3-899b-0cff63836d46' `
    -FirstName 'Ivan' `
    -LastName 'Ivanov' `
    -Email 'ivanivanov2@example.com' `
    -Phone '555666777' `
    -Timezone 'America/Los_Angeles' `
    -Enabled no `
    -SessionTimeout 45
```

Updates the specified user and returns the Action1 API response.

### Example 2: Disable a user

```powershell
Update-Action1User `
    -UserId '5e79941d-e4cc-40f3-899b-0cff63836d46' `
    -Enabled no
```

Sends `enabled` as `no`.

### Example 3: Preview a user update

```powershell
Update-Action1User `
    -UserId '5e79941d-e4cc-40f3-899b-0cff63836d46' `
    -Email 'ivanivanov2@example.com' `
    -WhatIf
```

Shows what would be updated without sending the PATCH request.

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

### -Email

Specifies the user's email address. The value must use a valid email format.

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

### -Enabled

Specifies whether the user is enabled. Accepted values are `yes` and `no`.

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

### -FirstName

Specifies the user's first name.

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

### -LastName

Specifies the user's last name.

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

### -Phone

Specifies the user's phone number.

The value can optionally start with `+` and must then contain 6 to 13 digits.

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

### -SessionTimeout

Specifies the user session timeout value in minutes.

Enter a timeout value between 5 and 1440 minutes. The command multiplies the
value by 60 and sends it to the API as the `session_timeout` body field in
seconds.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Timezone

Specifies the user's time zone using the region/location form, such as
`America/Los_Angeles`.

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

### -UserId

Specifies the ID of the Action1 user to update.

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

### System.Object

Returns the Action1 API response for the PATCH request.

## NOTES

Requires permission to manage users in Action1.

## RELATED LINKS

[Get-Action1User](Get-Action1User.md)
[Get-Action1Users](Get-Action1Users.md)
[Get-Action1UserRoles](Get-Action1UserRoles.md)
[Remove-Action1User](Remove-Action1User.md)
[Export-Action1UsersJson](Export-Action1UsersJson.md)
[Set-Action1Credentials](../configuration/Set-Action1Credentials.md)
