---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# New-Action1CompensatingControlRemediation

## SYNOPSIS

Creates a compensating control remediation record for an Action1 vulnerability.

## SYNTAX

```
New-Action1CompensatingControlRemediation [-CVEId] <String> [-Comment] <String> [-ProductName] <String>
 [<CommonParameters>]
```

## DESCRIPTION

Creates a new remediation record for a specific vulnerability in the current Action1 organization.

The command sends a POST request to the Action1 vulnerabilities remediation API endpoint for the specified CVE ID.

The request body includes the following values:

* `comment` - The value of the **Comment** parameter.
* `product_name` - The value of the **ProductName** parameter.

The command uses the module default organization configured by **Set-Action1DefaultOrg**.

## EXAMPLES

### Example 1: Create a compensating control remediation record

```powershell
New-Action1CompensatingControlRemediation `
    -CVEId 'CVE-2024-12345' `
    -Comment 'The vulnerable product is isolated and blocked from internet access.' `
    -ProductName 'Example Product'
```

Creates a compensating control remediation record for `CVE-2024-12345`.

### Example 2: Create a remediation record and review the returned object

```powershell
New-Action1CompensatingControlRemediation `
    -CVEId 'CVE-2024-12345' `
    -Comment 'The vulnerable component is not reachable from untrusted networks.' `
    -ProductName 'Example Product' |
    Format-List
```

Creates the remediation record and displays all fields returned by Action1.

## PARAMETERS

### -CVEId

Specifies the CVE ID of the vulnerability for which the remediation record should be created.

The value must match the CVE format `CVE-YYYY-NNN`, where:

* `YYYY` is a 4-digit year.
* `NNN` is a 3- to 6-digit CVE number.

Examples:

* `CVE-2024-123`
* `CVE-2024-12345`
* `CVE-2024-123456`

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

### -Comment

Specifies the remediation comment text to send to Action1.

The value is sent in the request body as `comment`.

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

### -ProductName

Specifies the product name associated with the compensating control remediation.

The value is sent in the request body as `product_name`.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe input to this command.

## OUTPUTS

### System.Object

Returns the remediation object returned by Action1.

## NOTES

Requires the default Action1 organization to be configured with **Set-Action1DefaultOrg**.

Requires permission to manage vulnerabilities in Action1.

The command uses **Write-Action1Debug** for debug logging.

## RELATED LINKS

[Get-Action1Vulnerability](Get-Action1Vulnerability.md)

[Get-Action1VulnerabilityRemediations](Get-Action1VulnerabilityRemediations.md)

[Remove-Action1CompensatingControlRemediation](Remove-Action1CompensatingControlRemediation.md)

[Remove-Action1CompensatingControlRemediations](Remove-Action1CompensatingControlRemediations.md)

[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
