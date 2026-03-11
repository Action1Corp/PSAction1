---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# New-Action1

## SYNOPSIS

Creates a new Action1 resource.

## SYNTAX

```powershell
New-Action1 [-Item] <String> [[-URI] <String>] [-Data] <Object> [<CommonParameters>]
```

## DESCRIPTION

`New-Action1` creates a new object in the remote API using a POST request.

The type of object being created is specified by the **Item** parameter.  
Depending on the selected item type, the function automatically determines the correct API endpoint using the module's internal URI lookup table.

If `Item` is set to **RawURI**, the request is sent directly to the URI specified by the **URI** parameter, bypassing the internal lookup logic.

The command requires valid authentication credentials and a valid access token. Use `Set-Action1Credentials` and any required authentication commands before calling this function.

## EXAMPLES

### Example 1

```powershell
PS C:\> New-Action1 -Item Organization -Data $OrgData
```

Creates a new Action1 organization using the data provided in $OrgData

### Example 2

```powershell
PS C:\> New-Action1 -Item EndpointGroup -Data $GroupData
```

Creates a new Action1 endpoint group.

### Example 3

```powershell
PS C:\> New-Action1 -Item RawURI -URI "/v1/custom/resource" -Data $Payload
```

Sends a POST request directly to a custom Action1 API endpoint using the provided payload.

## PARAMETERS

### -Item

Specifies the type of object to create.

Valid values are:

 - EndpointGroup

 - Organization

 - Automation

 - Remediation

 - DeferredRemediation

 - DeploySoftware

 - RawURI

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

Specifies the API endpoint path when Item is set to `RawURI`.

This parameter is ignored for other item types because the function determines the URI automatically.

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

### -Data

Specifies the request payload that will be sent to the API.
The structure depends on the type of item being created.

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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None. You cannot pipe objects to this command.

## OUTPUTS

### System.Object. Returns the API response object returned by the PushData request.

## NOTES

This function:

Uses the module's internal URI lookup table to determine API endpoints.

Requires a valid Action1 authentication token previously specified by `Set-Action1Credentials`.

Sends data using an HTTP POST request.

If the `RawURI` item type is used, the valid `URI` value must be supplied.

## RELATED LINKS

[Set-Action1Credentials](Set-Action1Credentials.md)