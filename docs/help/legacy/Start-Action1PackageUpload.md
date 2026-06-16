---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# Start-Action1PackageUpload

## SYNOPSIS

Uploads a package file to an Action1 software repository package version.

## SYNTAX

```
Start-Action1PackageUpload [-Package_ID] <String> [-Version_ID] <String> [-Filename] <String>
 [-Platform] <String> [[-BufferSize] <Int32>] [<CommonParameters>]
```

## DESCRIPTION

`Start-Action1PackageUpload` uploads a local package file to an existing Action1 software repository package version.

The command opens a resumable upload stream for the specified package and version, then sends the file in chunks by using HTTP `PUT` requests with `Content-Range` headers.

The package version and target platform are selected by the **Package_ID**, **Version_ID**, and **Platform** parameters. The **Platform** value must be either `Windows_32` or `Windows_64`.

The **BufferSize** parameter controls the maximum chunk size, in bytes. The default value is `24MB`. If the file is smaller than the configured buffer size, the command automatically reduces the buffer size to match the file length.

The command requires Action1 authentication to be configured before it is run.

## EXAMPLES

### Example 1

```powershell
PS C:\> Start-Action1PackageUpload -Package_ID "12345" -Version_ID "1.0.0" -Filename "C:\Packages\App.msi" -Platform Windows_64
```

Uploads `C:\Packages\App.msi` to package `12345`, version `1.0.0`, for the Windows 64-bit platform.

### Example 2

```powershell
PS C:\> Start-Action1PackageUpload -Package_ID "12345" -Version_ID "2.0.0" -Filename ".\installer.exe" -Platform Windows_32 -BufferSize 48MB
```

Uploads `.\installer.exe` to package `12345`, version `2.0.0`, for the Windows 32-bit platform. The upload uses a 48 MB chunk buffer.

### Example 3

```powershell
PS C:\> $packageId = "12345"
PS C:\> $versionId = "67890"
PS C:\> Start-Action1PackageUpload -Package_ID $packageId -Version_ID $versionId -Filename "C:\Installers\agent-x64.msi" -Platform Windows_64
```

Stores the package and version identifiers in variables, then uploads the package file for the Windows 64-bit platform.

## PARAMETERS

### -BufferSize

Specifies the upload chunk buffer size, in bytes.

Larger values reduce the number of upload requests but increase memory usage. Smaller values reduce memory usage but require more upload requests.

PowerShell size literals, such as `24MB` or `48MB`, can be used when calling the command.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: 24MB
Accept pipeline input: False
Accept wildcard characters: False
```

### -Filename

Specifies the path to the local package file to upload.

The file must exist and must be readable by the current PowerShell session.

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

### -Package_ID

Specifies the identifier of the Action1 software repository package.

The package must already exist in the selected Action1 organization.

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

### -Platform

Specifies the target platform for the uploaded package file.

Accepted values:

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

### -Version_ID

Specifies the identifier of the package version that receives the uploaded file.

The version must already exist for the package specified by **Package_ID**.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

You cannot pipe objects to this command.

## OUTPUTS

### None

This command performs the upload operation and writes progress information through the module debug output.

## NOTES

The command requires a valid Action1 authentication token in the current session. Use `Set-Action1Credentials` before running this command.

The selected package and package version must exist before the upload is started.

The upload uses a resumable chunked transfer workflow. During upload, progress is reported through `Write-Action1Debug` messages.

## RELATED LINKS

[Set-Action1Credentials](Set-Action1Credentials.md)

[Set-Action1Region](Set-Action1Region.md)

[New-Action1](New-Action1.md)

[Get-Action1](Get-Action1.md)
