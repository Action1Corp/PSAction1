---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1AutomationInstanceEndpointDetails

## SYNOPSIS

Gets result details for an endpoint in an automation instance in the current Action1 organization.

## SYNTAX

### AllDetails (Default)

```
Get-Action1AutomationInstanceEndpointDetails [-AutomationInstanceId] <String>
 [-EndpointId] <String> [-Limit <Int32>] [<CommonParameters>]
```

### AsPage

```
Get-Action1AutomationInstanceEndpointDetails [-AutomationInstanceId] <String>
 [-EndpointId] <String> [-AsPage] [-Limit <Int32>] [<CommonParameters>]
```

## DESCRIPTION

Gets endpoint result details from
`/automations/instances/{orgId}/{automationInstanceId}/endpoint-results/{endpointId}/details`
by using the module default organization configured by **Set-Action1DefaultOrg**.

By default, the command retrieves all API pages and returns individual detail
objects to the pipeline without changing their properties.

Use **AsPage** to return one envelope object per API page. Use **Limit** to
control how many detail records are requested per API page. The value must be
from 1 through 200. The default value is 200.

## EXAMPLES

### Example 1: Get all result details for an endpoint

```powershell
Get-Action1AutomationInstanceEndpointDetails `
    -AutomationInstanceId '11111111-1111-1111-1111-111111111111' `
    -EndpointId '22222222-2222-2222-2222-222222222222'
```

Gets all result details for the specified endpoint and automation instance in
the current organization.

### Example 2: Use positional IDs and a smaller API page size

```powershell
Get-Action1AutomationInstanceEndpointDetails `
    '11111111-1111-1111-1111-111111111111' `
    '22222222-2222-2222-2222-222222222222' -Limit 50
```

Retrieves all result details, requesting up to 50 records per API page.

### Example 3: Get result details as pages

```powershell
Get-Action1AutomationInstanceEndpointDetails `
    -AutomationInstanceId '11111111-1111-1111-1111-111111111111' `
    -EndpointId '22222222-2222-2222-2222-222222222222' `
    -AsPage -Limit 50
```

Gets page envelope objects for the specified endpoint and automation instance.

## PARAMETERS

### -AutomationInstanceId

Specifies the ID of the automation instance whose endpoint result details are
retrieved. The value cannot be null or empty.

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

### -EndpointId

Specifies the endpoint whose result details are retrieved. The value must be a
non-empty, valid GUID, using the same validation as **Get-Action1Endpoint**.
Explicit null, empty, or malformed values are rejected.

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

### -AsPage

Returns page envelope objects instead of individual detail objects.
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

Specifies how many detail records to request from Action1 per API page.
This controls the page size rather than the total number of returned records.

The value must be from 1 through 200. The default value is 200.

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

Returns endpoint result detail objects from Action1.

When **AsPage** is used, each page object contains `Items`, `PageNumber`,
`From`, `Limit`, `TotalItems`, and `NextPage`. The `Items` property contains
the detail records returned for that API page.

## NOTES

Requires the default Action1 organization to be configured with
**Set-Action1DefaultOrg**.

The command uses **Invoke-Action1PagedGetRequest** to retrieve results from
the Action1 API.

## RELATED LINKS

[Get-Action1AutomationInstanceEndpoints](Get-Action1AutomationInstanceEndpoints.md)
[Get-Action1AutomationInstance](Get-Action1AutomationInstance.md)
[Get-Action1AutomationInstances](Get-Action1AutomationInstances.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
