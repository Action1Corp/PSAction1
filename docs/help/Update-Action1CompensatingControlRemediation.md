---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Update-Action1CompensatingControlRemediation

## SYNOPSIS

Updates the comment of one compensating control remediation record for an Action1 vulnerability.

## SYNTAX

```powershell
Update-Action1CompensatingControlRemediation [-CVEId] <String> [-RemediationId] <String> [-Comment] <String> [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

Updates an existing compensating control remediation record for a specific vulnerability in the current Action1 organization.

The Action1 API allows updating only the remediation record comment. The command uses the module default organization configured by **Set-Action1DefaultOrg**.

## EXAMPLES

### Example 1: Update a remediation comment

```powershell
Update-Action1CompensatingControlRemediation `
    -CVEId 'CVE-2024-12345' `
    -RemediationId '03445606-d55d-41c5-b877-b9a21618ae79' `
    -Comment 'The application has been blocked from accessing the internet.'
```

Updates the comment for the specified compensating control remediation record.

### Example 2: Preview the update

```powershell
Update-Action1CompensatingControlRemediation `
    -CVEId 'CVE-2024-12345' `
    -RemediationId '03445606-d55d-41c5-b877-b9a21618ae79' `
    -Comment 'Updated compensating control details.' `
    -WhatIf
```

Shows what would be updated without sending the PATCH request.

## PARAMETERS

### -CVEId

Specifies the CVE ID that owns the remediation record.

The value must match the format `CVE-YYYY-NNN` through `CVE-YYYY-NNNNNN`, for example `CVE-2024-12345`.

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

### -RemediationId

Specifies the remediation record ID to update.

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

### -Comment

Specifies the new remediation comment.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
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

### CommonParameters

This cmdlet supports the common parameters: Verbose, Debug,
ErrorAction, ErrorVariable, WarningAction, WarningVariable,
OutBuffer, PipelineVariable, and OutVariable. For more information, see
[about_CommonParameters](https://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe input to this command.

## OUTPUTS

### System.Object

Returns the updated remediation object returned by Action1.

## NOTES

Requires permission to manage vulnerabilities in Action1.

## RELATED LINKS

[Get-Action1VulnerabilityRemediations](Get-Action1VulnerabilityRemediations.md)
[Remove-Action1CompensatingControlRemediation](Remove-Action1CompensatingControlRemediation.md)
[Set-Action1DefaultOrg](Set-Action1DefaultOrg.md)