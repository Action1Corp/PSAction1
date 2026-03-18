---

external help file: PSAction1-help.xml

Module Name: PSAction1

online version:

schema: 2.0.0

---



# Start-Action1PackageUpload



## SYNOPSIS



Uploads an Action1 package file to the software repository in chunks.



## SYNTAX



```powershell

Start-Action1PackageUpload [-Package_ID] <String> [-Version_ID] <String> [-Filename] <String>

 [-Platform] <String> [[-BufferSize] <Int32>] [<CommonParameters>]

```



## DESCRIPTION



`Start-Action1PackageUpload` uploads an Action1 package file to the remote software repository for a specific package version.

The upload `Platform` must be specified as `Windows_32` or `Windows_64`.

The upload is performed using a **resumable chunked upload process**. Chunked uploads allow large files to be transferred reliably and provide progress feedback during the upload process. The chunk size can be controlled using the `BufferSize` parameter (default is 24MB).


This command requires a valid Action1 API authentication token (set earlier in the session). See `Set-Action1Credentials`.



## EXAMPLES



### Example 1



```powershell

PS C:\> Start-Action1PackageUpload -Package_ID "12345" -Version_ID "1.0.0" -Filename "C:\Packages\App.msi" -Platform Windows_64

```



Uploads the file App.msi as version 1.0.0 of package 12345 for the Windows 64-bit platform.



### Example 2



```powershell

PS C:\> Start-Action1PackageUpload -Package_ID "12345" -Version_ID "2.0.0" -Filename ".\installer.exe" -Platform Windows_32 -BufferSize 48MB

```



Uploads the installer using a larger 48 MB upload buffer to reduce the number of upload chunks.



## PARAMETERS



### -Package_ID



Identifier of the package in the software repository.



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



### -Version_ID



Identifier of the version of the package that the file will be uploaded to.



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



### -Filename



Path to the file that will be uploaded.



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



### -Platform



Target platform for the package upload.



Valid values:



 - Windows_32

 - Windows_64



```yaml

Type: String

Parameter Sets: (All)

Aliases:

Accepted values: Windows_32, Windows_64



Required: True

Position: 3

Default value: None

Accept pipeline input: False

Accept wildcard characters: False

```



### -BufferSize



Size of the upload chunk buffer in bytes.



Larger buffers reduce the number of HTTP requests but increase memory usage.



Default value: **24 MB**.



```yaml

Type: Int32

Parameter Sets: (All)

Aliases:



Required: False

Position: 4

Default value: None

Accept pipeline input: False

Accept wildcard characters: False

```



### CommonParameters



This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).



## INPUTS



### None. You cannot pipe objects to this command.



## OUTPUTS



### None. This command performs the upload operation and reports progress using debug output.



## NOTES



Requires a valid authentication token in the current session.



The upload is performed using a resumable chunked transfer mechanism.



Progress information is displayed through Debug-Host messages.



## RELATED LINKS



[Set-Action1Credentials](Set-Action1Credentials.md)
