function Start-Action1PackageUpload {
    param(
        [Parameter(Mandatory)]
        [String]$Package_ID,
        [Parameter(Mandatory)]
        [String]$Version_ID,
        [Parameter(Mandatory)]
        [String]$Filename,
        [Parameter(Mandatory)]
        [ValidateSet(
            'Windows_32',
            'Windows_64'
        )]
        [String]$Platform,
        [int32]$BufferSize = 24Mb
    )
    $uri = "$Script:Action1_BaseURI/software-repository/all/$Package_ID/versions/$Version_ID/upload?platform=$Platform" 
    Write-Action1Debug "Base URI is $uri"
    $UploadTarget = ""
    Write-Action1Debug "Uploading file: '$Filename'"
    Write-Action1Debug "Writing in chunks of $BufferSize bytes."
    $FileData = [System.IO.File]::Open($Filename, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
    if ($FileData.Length -lt $BufferSize) {
         $BufferSize = $FileData.Length; 
         Write-Action1Debug "File is smaller than BufferSize, adjusting to $($FileData.Length)" 
    }
    $Buffer = New-Object byte[] $BufferSize
    $Place = 0

    $HeaderBase = @{
        'accept'                = '*/*'
        'X-Upload-Content-Type' = 'application/octet-stream'
    }

    try {
        $Headers = $HeaderBase.Clone()
        $Headers.Add('X-Upload-Content-Length', $($FileData.Length))
        Invoke-Action1ApiRequest -Method POST -Path $uri -Label 'Opening upload stream' -Headers $Headers -ErrorAction SilentlyContinue  
    }
    catch { 
        $UploadTarget = $_.Exception.Response.Headers['X-Upload-Location'] 
    } 

    Write-Action1Debug "Upload URI is $UploadTarget"

    while (($Read = $FileData.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
        $Headers = $HeaderBase.Clone()
        $Headers.Add('Content-Range', "bytes $($Place)-$($($Place + $Read-1))/$($FileData.Length)")
        $Headers.Add('Content-Length', "$($Read)")
        $Headers.Add('Content-Type', 'application/octet-stream')
        $Place += $Read
        try { 
            $response = Invoke-Action1ApiRequest `
                -Method PUT `
                -Path $UploadTarget `
                -Label "Uploading Package $($Package_ID)" `
                -Body $Buffer `
                -RawBody `
                -Headers $Headers `
                -ErrorAction SilentlyContinue         
        }
        catch {
            Write-Action1Debug "Last Status: $($_.Exception.Response.StatusCode)" 
        }

        if (($FileData.Length - $Place) -lt $BufferSize) { 
            $buffer = New-Object byte[] ($FileData.Length - $place) 
        }
        Write-Action1Debug "Upload $([math]::Round((($Place / $FileData.Length)*100),1))% Complete."

        if ($Buffer.Length -eq 0) { 
            Write-Action1Debug "Final Status:$($response.StatusCode)" 
        }
        else {
            Write-Action1Debug "Bytes Written: $($Buffer.Length)" 
        }
    }
    $FileData.Close()
}