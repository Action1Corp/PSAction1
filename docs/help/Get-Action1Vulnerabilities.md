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

```powershell
Get-Action1Vulnerabilities [[-RemediationStatus] <String>] [<CommonParameters>]
```

## DESCRIPTION

Gets vulnerable software records from the current Action1 organization by using the Action1 vulnerabilities API.

When **RemediationStatus** is specified, the request is filtered by the specified remediation status. The command uses the module default organization configured by **Set-Action1DefaultOrg**.

## EXAMPLES

### Example 1: Get all vulnerabilities

```powershell
Get-Action1Vulnerabilities
```

Gets all vulnerabilities visible to the authenticated Action1 account in the current organization.

### Example 2: Get vulnerabilities with compensating controls applied

```powershell
Get-Action1Vulnerabilities -RemediationStatus 'Control_applied'
```

Gets vulnerabilities where the remediation status is `Control_applied`.

### Example 3: Review overdue vulnerabilities

```powershell
Get-Action1Vulnerabilities -RemediationStatus 'Overdue' |
    Select-Object cve_id, name, remediation_status
```

Gets overdue vulnerabilities and selects key fields.

## PARAMETERS

### -RemediationStatus

Filters vulnerabilities by remediation status.

Accepted values:

- `Due soon`
- `Overdue`
- `Due later`
- `Control_applied`

```yaml
Type: String
Parameter Sets: (All)
Aliases:
Accepted values: Due soon, Overdue, Due later, Control_applied

Required: False
Position: 0
Default value: None
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

Returns vulnerability objects from Action1.

## NOTES

Requires the default Action1 organization to be configured with **Set-Action1DefaultOrg**.

## RELATED LINKS

[Get-Action1Vulnerability](Get-Action1Vulnerability.md)
[Get-Action1VulnerabilityRemediations](Get-Action1VulnerabilityRemediations.md)
[Remove-Action1VulnerabilityRemediations](Remove-Action1VulnerabilityRemediations.md)
[Set-Action1DefaultOrg](Set-Action1DefaultOrg.md)
