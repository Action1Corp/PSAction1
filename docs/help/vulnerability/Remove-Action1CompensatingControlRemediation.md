---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Remove-Action1CompensatingControlRemediation

## SYNOPSIS

Deletes one remediation record for an Action1 vulnerability.

## SYNTAX

```
Remove-Action1CompensatingControlRemediation [-CVEId] <String> [-RemediationId] <String> [-Force] [-WhatIf]
 [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

Deletes a specific remediation record for a specific vulnerability in the current Action1 organization.

The Action1 API requires both the CVE ID and the remediation ID to delete a remediation record.

The CVE ID must use the standard CVE format, such as `CVE-2024-12345`.

This command supports PowerShell confirmation. Use **-WhatIf** to preview the delete operation. Use **-Force** to bypass the confirmation prompt.

## EXAMPLES

### Example 1: Delete one remediation record

```powershell
Remove-Action1CompensatingControlRemediation -CVEId 'CVE-2024-12345' -RemediationId 'remediation-123'
```

Prompts for confirmation, then deletes the specified remediation record.

### Example 2: Preview deletion

```powershell
Remove-Action1CompensatingControlRemediation -CVEId 'CVE-2024-12345' -RemediationId 'remediation-123' -WhatIf
```

Shows what would be deleted without sending the DELETE request.

### Example 3: Delete without prompting

```powershell
Remove-Action1CompensatingControlRemediation -CVEId 'CVE-2024-12345' -RemediationId 'remediation-123' -Force
```

Deletes the remediation record without prompting for confirmation.

## PARAMETERS

### -CVEId

Specifies the CVE ID that owns the remediation record.

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

### -RemediationId

Specifies the remediation record ID to delete.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
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

Returns a status object with CVEId, RemediationId, Status, and Response.

## NOTES

Requires permission to manage vulnerabilities in Action1.

## RELATED LINKS

[Get-Action1VulnerabilityRemediations](Get-Action1VulnerabilityRemediations.md)
[Remove-Action1CompensatingControlRemediations](Remove-Action1CompensatingControlRemediations.md)
[Set-Action1DefaultOrg](Set-Action1DefaultOrg.md)
