---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Export-Action1VulnerabilitiesEndpointsCsv

## SYNOPSIS

Exports Action1 vulnerability endpoint details to a CSV file.

## SYNTAX

```powershell
Export-Action1VulnerabilitiesEndpointsCsv [[-Path] <String>] [-CVEIds <String[]>] [-RemediationStatus <String>] [-Score <String>] [<CommonParameters>]
```

## DESCRIPTION

Exports a CSV report that maps Action1 vulnerabilities to affected endpoints in the current Action1 organization.

The command can export endpoint details for all vulnerabilities returned by **Get-Action1Vulnerabilities**, optionally filtered by remediation status and severity score, or it can export endpoint details only for explicitly specified CVE IDs.

For each selected CVE ID, the command retrieves affected endpoints by using **Get-Action1VulnerabilityEndpoints**. When available, vulnerability metadata is retrieved by using **Get-Action1Vulnerability**.

The command writes the following CSV columns:

* `CVEId`
* `CVSSScore`
* `Severity`
* `RemediationStatus`
* `EndpointId`
* `EndpointName`
* `ApplicationName`
* `InstalledVersion`
* `AvailableUpdate`

The command creates the target directory when it does not already exist and overwrites the target CSV file if it already exists.

The command uses the module default organization configured by **Set-Action1DefaultOrg**.

## EXAMPLES

### Example 1: Export all vulnerability endpoint records to the default CSV file

```powershell
Export-Action1VulnerabilitiesEndpointsCsv
```

Exports vulnerability endpoint records to `Action1_VulnerabilitiesEndpoints.csv` in the current location.

### Example 2: Export critical vulnerability endpoint records to a specific file

```powershell
Export-Action1VulnerabilitiesEndpointsCsv -Path 'C:\Reports\CriticalVulnerabilityEndpoints.csv' -Score Critical
```

Exports endpoint records for vulnerabilities with a critical score to the specified CSV file.

### Example 3: Export overdue vulnerability endpoint records

```powershell
Export-Action1VulnerabilitiesEndpointsCsv -Path 'C:\Reports\OverdueVulnerabilityEndpoints.csv' -RemediationStatus Overdue
```

Exports endpoint records for vulnerabilities with an overdue remediation status to the specified CSV file.

### Example 4: Export endpoint records for specific CVE IDs

```powershell
Export-Action1VulnerabilitiesEndpointsCsv -Path '.\SelectedCveEndpoints.csv' -CVEIds 'CVE-2024-12345', 'CVE-2024-23456'
```

Exports endpoint records only for the specified CVE IDs.

When **CVEIds** is specified, **RemediationStatus** and **Score** are not used to select CVEs.

### Example 5: Export and import the CSV data for review

```powershell
$Path = 'C:\Reports\VulnerabilityEndpoints.csv'
Export-Action1VulnerabilitiesEndpointsCsv -Path $Path -RemediationStatus All_except_control_applied -Score High
Import-Csv -Path $Path | Format-Table CVEId, Severity, EndpointName, ApplicationName, InstalledVersion, AvailableUpdate
```

Exports high severity vulnerability endpoint records, excluding vulnerabilities with applied compensating controls, and displays selected CSV columns.

## PARAMETERS

### -Path

Specifies the path to the CSV file to create.

If the path contains a directory that does not exist, the command creates the directory. If the file already exists, the command overwrites it.

If this parameter is not specified, the command creates `Action1_VulnerabilitiesEndpoints.csv` in the current location.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 0
Default value: (Join-Path -Path (Get-Location) -ChildPath 'Action1_VulnerabilitiesEndpoints.csv')
Accept pipeline input: False
Accept wildcard characters: False
```

### -CVEIds

Specifies one or more CVE IDs whose affected endpoint records should be exported.

Each value must match the `CVE-YYYY-NNN` or `CVE-YYYY-NNNNNN` format.

When this parameter is specified, the command uses only the provided CVE IDs. **RemediationStatus** and **Score** are not used to select CVEs.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RemediationStatus

Specifies the remediation status used to select vulnerabilities when **CVEIds** is not specified.

The default value is `All`.

The acceptable values for this parameter are:

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

Required: False
Position: Named
Default value: All
Accept pipeline input: False
Accept wildcard characters: False
```

### -Score

Specifies the vulnerability severity score used to select vulnerabilities when **CVEIds** is not specified.

The default value is `All`.

The acceptable values for this parameter are:

* `Critical`
* `High`
* `Medium`
* `Low`
* `All`

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: All
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe input to this command.

## OUTPUTS

### None

This command does not return pipeline output. It creates or overwrites a CSV file at the specified path.

## NOTES

Requires the default Action1 organization to be configured with **Set-Action1DefaultOrg**.

Requires permission to view vulnerabilities in Action1.

The command displays progress while processing CVE IDs.

## RELATED LINKS

[Get-Action1Vulnerabilities](Get-Action1Vulnerabilities.md)
[Get-Action1Vulnerability](Get-Action1Vulnerability.md)
[Get-Action1VulnerabilityEndpoints](Get-Action1VulnerabilityEndpoints.md)
[Set-Action1DefaultOrg](Set-Action1DefaultOrg.md)
