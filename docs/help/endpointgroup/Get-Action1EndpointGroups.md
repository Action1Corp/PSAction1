---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1EndpointGroups

## SYNOPSIS

Gets endpoint groups for the current Action1 organization.

## SYNTAX

### AllEndpointGroups (Default)
```
Get-Action1EndpointGroups [-Limit <Int32>] [<CommonParameters>]
```

### AsPage
```
Get-Action1EndpointGroups [-AsPage] [-Limit <Int32>] [<CommonParameters>]
```

## DESCRIPTION

Gets endpoint group records from the current Action1 organization by using the
Action1 endpoint groups API.

The command uses the module default organization configured by
**Set-Action1DefaultOrg**.

Use **AsPage** to return one object per API page. Page mode is intended for
export commands and other callers that need to process endpoint groups page by
page without materializing the whole collection first.

## EXAMPLES

### Example 1: Get all endpoint groups

```powershell
Get-Action1EndpointGroups
```

Gets all endpoint groups in the current organization.

### Example 2: Review selected endpoint group fields

```powershell
Get-Action1EndpointGroups |
    Select-Object id, name, description
```

Gets endpoint groups and selects key fields.

## PARAMETERS

### -AsPage

Returns page envelope objects instead of individual endpoint group objects.
Each page object contains `Items`, `PageNumber`, `From`, `Limit`,
`TotalItems`, and `NextPage`.

```yaml
Type: SwitchParameter
Parameter Sets: AsPage
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Limit

Specifies how many endpoint groups to request from Action1 per API page.

The value must be from 1 through 2147483647. The default value is 200.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 200
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

Returns endpoint group objects from Action1.

When **AsPage** is used, each page object contains `Items`, `PageNumber`,
`From`, `Limit`, `TotalItems`, and `NextPage`.

## NOTES

Requires the default Action1 organization to be configured with
**Set-Action1DefaultOrg**.

The command retrieves paged results from the Action1 API and returns endpoint
group objects to the pipeline.

## RELATED LINKS

[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
