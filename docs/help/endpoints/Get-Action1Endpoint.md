---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Get-Action1Endpoint

## SYNOPSIS

Gets one managed endpoint from the current Action1 organization.

## SYNTAX

```
Get-Action1Endpoint [-EndpointId] <String> [<CommonParameters>]
```

## DESCRIPTION

Gets detailed information about a specific managed endpoint by using the Action1 endpoints API.

The command uses the module default organization configured by **Set-Action1DefaultOrg**.

## EXAMPLES

### Example 1: Get an endpoint by ID

```powershell
Get-Action1Endpoint -EndpointId '5e79941d-e4cc-40f3-899b-0cff63836d46'
```

Gets details for the specified endpoint in the current Action1 organization.

### Example 2: Display endpoint details

```powershell
Get-Action1Endpoint -EndpointId '5e79941d-e4cc-40f3-899b-0cff63836d46' |
    Format-List
```

Gets the endpoint and displays all returned fields.

## PARAMETERS

### -EndpointId

Specifies the ID of the managed endpoint to retrieve.

The endpoint ID must use the standard GUID format, such as
`5e79941d-e4cc-40f3-899b-0cff63836d46`.

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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe input to this command.

## OUTPUTS

### System.Object

Returns the managed endpoint object returned by Action1.

## NOTES

Requires the default Action1 organization to be configured with **Set-Action1DefaultOrg**.

## RELATED LINKS

[Get-Action1Endpoints](Get-Action1Endpoints.md)
[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
