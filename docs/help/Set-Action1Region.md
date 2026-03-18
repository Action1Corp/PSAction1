---

external help file: PSAction1-help.xml

Module Name: PSAction1

online version:

schema: 2.0.0

---



# Set-Action1Region



## SYNOPSIS



Sets the Action1 API region endpoint used by the PSAction1 module.



## SYNTAX



```powershell

Set-Action1Region [-Region] <String> [<CommonParameters>]

```



## DESCRIPTION



`Set-Action1Region` configures the base API endpoint used by the module for all subsequent requests.



Different Action1 regions correspond to different service API endpoints.

This command updates the internal script scope variable so that all module commands send requests to the correct regional API endpoint.



Run this command before executing other commands in the module to ensure a specific regional environment is targeted.



## EXAMPLES



### Example 1



```powershell

PS C:\> Set-Action1Region -Region Europe

```



Configures PSAction1 module to use the Europe API endpoint.



### Example 2



```powershell

PS C:\> Set-Action1Region -Region NorthAmerica

```



Configures PSAction1 module to use the NorthAmerica API endpoint.



### Example 3



```powershell

PS C:\> Set-Action1Region -Region Australia

```



Configures PSAction1 module to use the Australia API endpoint.



## PARAMETERS



### -Region



Specifies the API region to use.



Supported values are:



 - NorthAmerica



 - Europe



 - Australia



```yaml

Type: String

Parameter Sets: (All)

Aliases:

Accepted values: NorthAmerica, Europe, Australia



Required: True

Position: 0

Default value: None

Accept pipeline input: False

Accept wildcard characters: False

```



### CommonParameters



This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).



## INPUTS



### None. You cannot pipe objects to this command.



## OUTPUTS



### None. This command only sets an internal module variable used to determine the API base URI.



## NOTES



This command must typically be executed before making API requests so that PSAction1 module communicates with the correct regional service endpoint.



The selected region affects all subsequent commands in the current PowerShell session.



## RELATED LINKS
