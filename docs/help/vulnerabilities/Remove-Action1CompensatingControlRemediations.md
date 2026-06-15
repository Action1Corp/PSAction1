---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Remove-Action1CompensatingControlRemediations

## SYNOPSIS

Deletes compensating control remediation records for vulnerabilities with remediation status `Control_applied`.

## SYNTAX

```
Remove-Action1CompensatingControlRemediations [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

Finds vulnerabilities in the current Action1 organization where the remediation status is `Control_applied`.

The command processes vulnerabilities across all severity scores. Internally, it queries vulnerabilities with remediation status `Control_applied` and score `All`.

For each matching vulnerability, the command gets remediation records, displays the remediation records that are candidates for deletion, and deletes each remediation record after confirmation.

This command supports PowerShell confirmation. Use **-WhatIf** to preview delete operations. Use **-Force** to bypass confirmation prompts.

The command uses the module default organization configured by **Set-Action1DefaultOrg**.

## EXAMPLES

### Example 1: Remove compensating control remediation records

```powershell
Remove-Action1CompensatingControlRemediations
```

Gets vulnerabilities with remediation status `Control_applied` across all severity scores, displays remediation records to delete, prompts for confirmation, and deletes selected records.

### Example 2: Preview compensating control cleanup

```powershell
Remove-Action1CompensatingControlRemediations -WhatIf
```

Shows delete operations that would be performed without deleting remediation records.

### Example 3: Remove without prompting

```powershell
Remove-Action1CompensatingControlRemediations -Force
```

Deletes remediation records for vulnerabilities with remediation status `Control_applied` across all severity scores without prompting for confirmation.

### Example 4: Store the cleanup summary

```powershell
$Summary = Remove-Action1CompensatingControlRemediations -Force

$Summary | Format-List
```

Deletes matching remediation records without prompting and stores the returned summary object in `$Summary`.

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

Bypasses confirmation prompts for individual remediation deletions. **-WhatIf** is still honored when it is specified.

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

Returns a summary object with counts for processed vulnerabilities and remediation deletion results.

The summary object includes the following properties:

* `VulnerabilitiesProcessed`
* `RemediationsFound`
* `RemediationsRemoved`
* `RemediationsSkipped`
* `RemediationsFailed`
* `RemediationStatus`

## NOTES

Deleting remediation records is irreversible. Test with **-WhatIf** before using **-Force**.

This command is intentionally scoped to vulnerabilities with remediation status `Control_applied`.

This command processes all severity scores.

Requires permission to view and manage vulnerabilities in Action1.

Requires the default Action1 organization to be configured with **Set-Action1DefaultOrg**.

## RELATED LINKS

[Get-Action1Vulnerabilities](Get-Action1Vulnerabilities.md)
[Get-Action1VulnerabilityRemediations](Get-Action1VulnerabilityRemediations.md)
[Remove-Action1CompensatingControlRemediation](Remove-Action1CompensatingControlRemediation.md)
[Set-Action1DefaultOrg](Set-Action1DefaultOrg.md)
