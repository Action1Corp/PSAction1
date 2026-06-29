---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1Vulnerabilities

## SYNOPSIS

Gets vulnerabilities for the current Action1 organization.

## SYNTAX

```
Get-Action1Vulnerabilities [[-RemediationStatus] <String>] [[-Score] <String>] [<CommonParameters>]
```

## DESCRIPTION

Gets vulnerable software records from the current Action1 organization by using the Action1 vulnerabilities API.

By default, the command returns vulnerabilities with the remediation status `Control_applied` and severity score `Critical`.

Use **RemediationStatus** to filter vulnerabilities by remediation status.

Use **Score** to filter vulnerabilities by severity score.

To disable one of these filters, specify `All` for the corresponding parameter.

The command uses the module default organization configured by **Set-Action1DefaultOrg**.

## EXAMPLES

### Example 1: Get critical vulnerabilities with compensating controls applied

```powershell
Get-Action1Vulnerabilities
```

Gets vulnerabilities in the current organization where the remediation status is `Control_applied` and the score is `Critical`.

This is the default behavior.

### Example 2: Get all vulnerabilities

```powershell
Get-Action1Vulnerabilities -RemediationStatus All -Score All
```

Gets all vulnerabilities visible to the authenticated Action1 account in the current organization without filtering by remediation status or score.

### Example 3: Get all vulnerabilities with compensating controls applied

```powershell
Get-Action1Vulnerabilities -RemediationStatus Control_applied -Score All
```

Gets vulnerabilities where the remediation status is `Control_applied`, regardless of severity score.

### Example 4: Get critical overdue vulnerabilities

```powershell
Get-Action1Vulnerabilities -RemediationStatus Overdue
```

Gets overdue vulnerabilities with the default score filter `Critical`.

### Example 5: Get all overdue vulnerabilities regardless of score

```powershell
Get-Action1Vulnerabilities -RemediationStatus Overdue -Score All
```

Gets overdue vulnerabilities regardless of severity score.

### Example 6: Get high severity vulnerabilities due soon

```powershell
Get-Action1Vulnerabilities -RemediationStatus Due_soon -Score High
```

Gets vulnerabilities where the remediation status is `Due_soon` and the score is `High`.

### Example 7: Review overdue vulnerabilities

```powershell
Get-Action1Vulnerabilities -RemediationStatus Overdue -Score All |
    Select-Object cve_id, name, remediation_status, score
```

Gets overdue vulnerabilities and selects key fields.

## PARAMETERS

### -RemediationStatus

Filters vulnerabilities by remediation status.

Specify `All` to disable remediation status filtering.

Accepted values:

* `Overdue`
* `Due_soon`
* `Overdue_due_soon`
* `Due_later`
* `Control_applied`
* `All_except_control_applied`
* `All`

```yaml
Type: String
Parameter Sets: (All)
Aliases:
Accepted values: Overdue, Due_soon, Overdue_due_soon, Due_later, Control_applied, All_except_control_applied, All

Required: False
Position: 0
Default value: Control_applied
Accept pipeline input: False
Accept wildcard characters: False
```

### -Score

Filters vulnerabilities by severity score.

Specify `All` to disable score filtering.

Accepted values:

* `Critical`
* `High`
* `Medium`
* `Low`
* `All`

```yaml
Type: String
Parameter Sets: (All)
Aliases:
Accepted values: Critical, High, Medium, Low, All

Required: False
Position: 1
Default value: Critical
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

Returns vulnerability objects from Action1.

## NOTES

Requires the default Action1 organization to be configured with **Set-Action1DefaultOrg**.

The command retrieves paged results from the Action1 API and returns vulnerability objects to the pipeline.

## RELATED LINKS

[Get-Action1Vulnerability](Get-Action1Vulnerability.md)

[Get-Action1VulnerabilityRemediations](Get-Action1VulnerabilityRemediations.md)

[Remove-Action1VulnerabilityRemediations](Remove-Action1VulnerabilityRemediations.md)

[Set-Action1DefaultOrg](Set-Action1DefaultOrg.md)
