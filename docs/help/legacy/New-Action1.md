---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# New-Action1

## SYNOPSIS

Creates a new Action1 object.

## SYNTAX

```
New-Action1 [-Item] <String> [[-URI] <String>] [-Data] <Object> [<CommonParameters>]
```

## DESCRIPTION

`New-Action1` creates a new object in Action1 by sending a POST request to the Action1 API.

The object type is selected with the **Item** parameter. For supported item types, the function resolves the API endpoint from the module's internal URI lookup table and sends the supplied **Data** object as the request body.

When **Item** is set to `RawURI`, the function bypasses the internal URI lookup table and sends the POST request directly to the API path provided in **URI**.

The command requires valid Action1 authentication. For organization-scoped item types, the default organization must also be configured before running this command.

## EXAMPLES

### Example 1

```powershell
PS C:\> $OrgData = [PSCustomObject]@{
    name = 'Contoso'
}
PS C:\> New-Action1 -Item Organization -Data $OrgData
```

Creates a new Action1 organization using the data in `$OrgData`.

### Example 2

```powershell
PS C:\> $GroupData = Get-Action1 -Query Settings -For EndpointGroup
PS C:\> $GroupData.name = 'Production Servers'
PS C:\> New-Action1 -Item EndpointGroup -Data $GroupData
```

Creates a new Action1 endpoint group from an endpoint group template object.

### Example 3

```powershell
PS C:\> $AutomationData = Get-Action1 -Query Settings -For Automation
PS C:\> $AutomationData.name = 'Weekly maintenance'
PS C:\> New-Action1 -Item Automation -Data $AutomationData
```

Creates a new Action1 automation from an automation template object.

### Example 4

```powershell
PS C:\> $Payload = [PSCustomObject]@{
    name = 'Custom object'
}
PS C:\> New-Action1 -Item RawURI -URI '/v1/custom/resource' -Data $Payload
```

Sends a POST request directly to the specified API path using the supplied payload.

## PARAMETERS

### -Data

Specifies the request body to send to the Action1 API.

The required object structure depends on the selected **Item** value and the corresponding Action1 API endpoint. Template objects for several supported item types can be retrieved with `Get-Action1 -Query Settings -For <Type>`.

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Item

Specifies the type of Action1 object to create.

Accepted values:

- EndpointGroup
- Organization
- Automation
- Remediation
- DeferredRemediation
- DeploySoftware
- RawURI

When this parameter is set to `RawURI`, the **URI** parameter must also be supplied.

```yaml
Type: String
Parameter Sets: (All)
Aliases:
Accepted values: EndpointGroup, Organization, Automation, Remediation, DeferredRemediation, DeploySoftware, RawURI

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -URI

Specifies a literal Action1 API path used for a raw POST request.

This parameter is required when **Item** is set to `RawURI`. For all other **Item** values, the function determines the API path automatically from the module's internal URI lookup table.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe objects to this command.

## OUTPUTS

### System.Object

Returns the response object produced by the Action1 API request. If the API request fails, or if **Item** is `RawURI` and **URI** is not supplied, the function returns `$null`.

## NOTES

This command sends data using an HTTP POST request through the module's internal API request helper.

Use `Set-Action1Credentials` before running this command.

For organization-scoped item types, set the default organization before running this command.

When using `RawURI`, provide a valid API path in **URI**.

## RELATED LINKS

[Get-Action1](Get-Action1.md)

[Update-Action1](Update-Action1.md)

[Set-Action1Credentials](Set-Action1Credentials.md)

[Set-Action1DefaultOrg](Set-Action1DefaultOrg.md)
