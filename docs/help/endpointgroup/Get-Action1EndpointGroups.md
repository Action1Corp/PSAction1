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

```
Get-Action1EndpointGroups [<CommonParameters>]
```

## DESCRIPTION

Gets endpoint group records from the current Action1 organization by using the
Action1 endpoint groups API.

The command uses the module default organization configured by
**Set-Action1DefaultOrg**.

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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction,
-ErrorVariable, -InformationAction, -InformationVariable, -OutVariable,
-OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable.
For more information, see
[about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe input to this command.

## OUTPUTS

### System.Object

Returns endpoint group objects from Action1.

## NOTES

Requires the default Action1 organization to be configured with
**Set-Action1DefaultOrg**.

The command retrieves paged results from the Action1 API and returns endpoint
group objects to the pipeline.

## RELATED LINKS

[Set-Action1DefaultOrg](../configuration/Set-Action1DefaultOrg.md)
