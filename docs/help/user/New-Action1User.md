---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# New-Action1User

## SYNOPSIS

Creates an Action1 user.

## SYNTAX

```
New-Action1User -FirstName <String> -LastName <String> -Email <String> -Password <String> [-Phone <String>]
 [-Timezone <String>] [-Enabled <String>] [-SessionTimeout <Int32>] [-Force] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

## DESCRIPTION

`New-Action1User` calls the Action1 users API and creates a user with the
specified profile and sign-in values.

The requested POST endpoint is `/users`.

The command always sends `first_name`, `last_name`, `email`, and `password`.
Optional fields are added to the request body only when their parameters are
specified. **-SessionTimeout** accepts a value in minutes and sends the API
`session_timeout` field in seconds. **-Enabled** accepts `yes` or `no`.

This command supports PowerShell confirmation. Use **-WhatIf** to preview the
create operation without sending the POST request. Use **-Confirm** to prompt
for confirmation before sending the POST request. Use **-Force** to bypass
confirmation prompts.

## EXAMPLES

### Example 1: Create a user

```powershell
New-Action1User `
    -FirstName 'Piotr' `
    -LastName 'Cyra' `
    -Email 'piotrivanov9@example.com' `
    -Password 'Madeira2025A' `
    -Phone '555666777' `
    -Timezone 'America/Los_Angeles' `
    -Enabled yes `
    -SessionTimeout 30
```

Creates the user and returns the Action1 API response. The session timeout is
sent to the API as `1800` seconds.

### Example 2: Create a user with only mandatory values

```powershell
New-Action1User `
    -FirstName 'Piotr' `
    -LastName 'Cyra' `
    -Email 'piotrivanov9@example.com' `
    -Password 'Madeira2025A'
```

Creates the user without sending optional `phone`, `timezone`, `enabled`, or
`session_timeout` fields.

### Example 3: Preview user creation

```powershell
New-Action1User `
    -FirstName 'Piotr' `
    -LastName 'Cyra' `
    -Email 'piotrivanov9@example.com' `
    -Password 'Madeira2025A' `
    -WhatIf
```

Shows what would be created without sending the POST request.

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

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Enabled

Specifies whether the user is enabled. Accepted values are `yes` and `no`.

When omitted, the command does not send the `enabled` field.

```yaml
Type: String
Parameter Sets: (All)
Aliases:
Accepted values: yes, no

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

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Force

Bypasses confirmation prompts. **-WhatIf** is still honored when it is specified.

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

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Password

Specifies the user's password.

The password must be at least 12 characters long, contain at least one number,
and contain upper and lower case letters.

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

### -Phone

Specifies the user's phone number.

The value must be 30 characters or fewer.

When omitted, the command does not send the `phone` field.

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
seconds. When omitted, the command does not send the `session_timeout` field.

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

When omitted, the command does not send the `timezone` field.

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

Returns the Action1 API response for the POST request.

## NOTES

Requires permission to manage users in Action1.

## RELATED LINKS

[Get-Action1User](Get-Action1User.md)
[Get-Action1Users](Get-Action1Users.md)
[Get-Action1UserRoles](Get-Action1UserRoles.md)
[Update-Action1User](Update-Action1User.md)
[Remove-Action1User](Remove-Action1User.md)
[Export-Action1UsersJson](Export-Action1UsersJson.md)
[Set-Action1Credentials](../configuration/Set-Action1Credentials.md)
