# Name: PSAction1
# Description: Powershell module for working with the Action1 API.

# Documentation: https://github.com/Action1Corp/PSAction1/
# Use Action1 Roadmap system (https://roadmap.action1.com/) to submit feedback or enhancement requests.

# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# © Action1 Corporation

$Script:ModuleRoot = $PSScriptRoot

$ConfigurationFiles = @(
    'Private\Configuration\Action1.Defaults.ps1'
    'Private\Configuration\Action1.Hosts.ps1'
    'Private\Configuration\Action1.UriMap.ps1'
    'Private\Initialization\Initialize-Action1ModuleState.ps1'
    'Private\Templates\RemediationTemplate.ps1'
    'Private\Templates\PackageDeployTemplate.ps1'
)

foreach ($RelativePath in $ConfigurationFiles) {
    . (Join-Path $Script:ModuleRoot $RelativePath)
}

Get-ChildItem -Path (Join-Path $Script:ModuleRoot 'Private') -Filter '*.ps1' -Recurse |
    Where-Object {
        $_.FullName -notmatch '\\Private\\Configuration\\' -and
        $_.FullName -notmatch '\\Private\\Initialization\\' -and
        $_.FullName -notmatch '\\Private\\Templates\\'
    } |
    Sort-Object FullName |
    ForEach-Object {
        . $_.FullName
    }

Get-ChildItem -Path (Join-Path $Script:ModuleRoot 'Public') -Filter '*.ps1' -Recurse |
    Sort-Object FullName |
    ForEach-Object {
        . $_.FullName
    }


function Initialize-Action1Token {
    [CmdletBinding()]
    param()

    if (
        ($null -ne $Script:Action1_Token) -and
        ($null -ne $Script:Action1_Token.access_token) -and
        ($Script:Action1_Token.expires_at -ge (Get-Date))
    ) {
        Write-Action1Debug "Current token is valid."
        return $true
    }

    Write-Action1Debug "Token not set or expired, fetching new token."

    $token = Request-Action1Token

    if ($null -ne $token) {
        $Script:Action1_Token = $token
        Write-Action1Debug "Token refresh successful."
        return $true
    }

    Write-Error "Token could not be refreshed, check for errors in output."
    return $false
}

function Initialize-Action1Region {
    [CmdletBinding()]
    param()

    if (-not [string]::IsNullOrWhiteSpace($Script:Action1_BaseURI)) {
        return $true
    }

    if (-not $Script:Action1_Interactive) {
        throw "Region not set. Call Set-Action1Region prior to making API calls."
    }

    $regions = @($Script:Action1_Hosts.GetEnumerator())

    while ([string]::IsNullOrWhiteSpace($Script:Action1_BaseURI)) {

        for ($i = 0; $i -lt $regions.Count; $i++) {
            Write-Host "$i : $($regions[$i].Key)"
        }

        $selection = Read-Host -Prompt 'Select your data center region'

        $index = 0
        if (
            [int]::TryParse($selection, [ref]$index) -and
            $index -ge 0 -and
            $index -lt $regions.Count
        ) {
            $Script:Action1_BaseURI = $regions[$index].Value
        }
        else {
            Write-Warning "Invalid selection."
        }
    }
    return $true
}

function Initialize-Action1DefaultOrg {
    [CmdletBinding()]
    param()

    if ($null -eq $Script:Action1_Default_Org) {
        if ($Script:Action1_Interactive) {
            Set-Action1DefaultOrg

            if ($null -eq $Script:Action1_Default_Org) {
                throw "Default organization was not selected."
            }
        }
        else {
            throw "Default Org not set. Call Set-Action1DefaultOrg before making API calls."
        }
    }
    return $Script:Action1_Default_Org
}

function Request-Action1Token {
    [CmdletBinding()]
    param()

    if (Initialize-Action1Region) {
        if ([string]::IsNullOrEmpty($Script:Action1_APIKey) -or [string]::IsNullOrEmpty($Script:Action1_Secret)) {
            if ($Script:Action1_Interactive) {
                Set-Action1Credentials 
            }
            else { 
                Write-Error "Authentication details are not set, call Set-Action1Credentials prior to making any calls to the API."
                exit
            } 
        }
        try {
            $Token = Invoke-Action1ApiRequest `
                -Method POST `
                -Path "$Script:Action1_BaseURI/oauth2/token" `
                -Label 'Request OAuth2 token' `
                -Body @{
                    client_id     = $Script:Action1_APIKey
                    client_secret = $Script:Action1_Secret
                } `
                -SkipAuthenticationCheck
            $Token | Add-Member -MemberType NoteProperty -Name "expires_at" -Value $(Get-Date).AddSeconds(([int]$Token.expires_in - 5)) #Expire token 5 seconds early to avoid race condition timeouts.
            return $Token
        }
        catch [System.Net.WebException] {
            Write-Error "Error fetching auth token: $($_)."
            Write-Error $Token
            return $null
        }     
    }
}

function Join-QueryString {
    param(
        [string]$QueryString,
        [string]$Argument
    )

    if ($QueryString) {
        "$QueryString&$Argument"
    }
    else {
        $Argument
    }
}

function Invoke-Action1ApiRequest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
        [string]$Method,
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Label,
        [hashtable]$Headers,
        [object]$Body,
        [switch]$RawBody,
        [string]$AddArgs,
        [switch]$RawResponse,
        [switch]$SkipAuthenticationCheck
    )

    if ($AddArgs) {
        $Path += "?{0}" -f $AddArgs
    }

    $headers = @{}

    if (-not $SkipAuthenticationCheck) {
        if (Initialize-Action1Token) {
            $headers.Authorization = "Bearer $($Script:Action1_Token.access_token)"
        }
    }

    $headers['Content-Type'] = 'application/json; charset=utf-8'

    if ($Headers) {
        foreach ($key in @($Headers.Keys)) {
            $headers[$key] = $Headers[$key]
        }
    }

    $requestBody = $null

    if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
        if ($RawBody) {
            $requestBody = $Body
            Write-Action1Debug "Raw request body supplied. Type: $($requestBody.GetType().FullName)"
        }
        else {
            $requestBody = ConvertTo-Json -InputObject $Body -Depth 10
            Write-Action1Debug "JSON Data to be sent:`n$requestBody"  
        }
    }

    $invokeWebRequestParams = @{
        Uri             = $Path
        Method          = $Method
        UseBasicParsing = $true
        Headers         = $headers
        ErrorAction     = 'Stop'
    }

    if ($null -ne $requestBody) {
        $invokeWebRequestParams.Body = $requestBody
    }

    $retry429Count = 0

    while ($true) {
        Write-Action1Debug "$Method request to $Path. RawResponse flag is $RawResponse"
        try {
            if($Script:Action1_DebugEnabled){$webRequestSW = [System.Diagnostics.Stopwatch]::StartNew()}

            $response = Invoke-WebRequest @invokeWebRequestParams

            if($Script:Action1_DebugEnabled){
                $webRequestSW.Stop()
                Write-Action1Debug ("{2} request to {0} took {1}ms" -f $Path, $($webRequestSW.ElapsedMilliseconds), $Method)
            }

            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
                Write-Action1Debug ("Success response code {0} for {1} to {2}" -f $($response.StatusCode), $Method, $Path)
                if ($RawResponse) {
                    return $response.Content
                }

                if ([string]::IsNullOrWhiteSpace($response.Content)) {
                    return $null
                }

                return ConvertFrom-Json -InputObject $response.Content
            }

            Write-Action1Debug "Error processing $($Label): HTTP status code $($response.StatusCode)."
            return $null
        }
        catch {
            $statusCode = $null

            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            Write-Action1Debug ("Failed response code {0} for {1} to {2}" -f $statusCode, $Method, $Path)

            if ($statusCode -eq 429) {
                
                $retryTimeout = [Math]::Pow(2,$retry429Count) * $Script:Action1_429RetryBaseTimeout
                $retry429Count++

                Write-Action1Debug ("429 received for '{0}'. Retry #{1}. Sleeping {2} ms." -f $Label, $retry429Count, $retryTimeout)
                Start-Sleep -Milliseconds $retryTimeout
                continue
            }

            Write-Action1Debug "Error processing $($Label): $($_.Exception.Message)"
            return $null
        }
    }
}

function Invoke-Action1PagedGetRequest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Label,
        [string]$AddArgs,
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Offset = 0,
        [ValidateRange(1, [int]::MaxValue)]
        [int]$Limit = 200
    )

    $RequestArgs = $AddArgs
    $RequestArgs = Join-QueryString -QueryString $RequestArgs -Argument "from=$Offset"
    $RequestArgs = Join-QueryString -QueryString $RequestArgs -Argument "limit=$Limit"

    $Page = Invoke-Action1ApiRequest -Method GET -Path $Path -Label $Label -AddArgs $RequestArgs

    if ($null -eq $Page) {
        Write-Action1Debug "[$Label] Page 1 returned null. Stopping pagination."
        return $null
    }

    if ($Page.PSObject.Properties.Name -notcontains 'items') {
        Write-Action1Debug "[$Label] Response is not a paged result. Returning response as-is."
        $Page
        return
    }

    $GetPageItemCount = {
        param([object]$CurrentPage)

        if ($null -eq $CurrentPage) {
            return 0
        }

        if ($CurrentPage.PSObject.Properties.Name -notcontains 'items') {
            return 0
        }

        if ($null -eq $CurrentPage.items) {
            return 0
        }

        return @($CurrentPage.items).Count
    }

    $PageNumber = 1
    $ItemCount = & $GetPageItemCount $Page

    Write-Action1Debug "[$Label] Processing page $PageNumber. Items: $ItemCount"

    foreach ($Item in @($Page.items)) {
        $Item
    }

    while (-not [string]::IsNullOrEmpty($Page.next_page)) {
        $PageNumber++
        Write-Action1Debug "[$Label] Requesting page $PageNumber..."

        $Page = Invoke-Action1ApiRequest -Method GET -Path $Page.next_page -Label $Label

        if ($null -eq $Page) {
            Write-Action1Debug "[$Label] Page $PageNumber returned null. Stopping pagination."
            break
        }

        $ItemCount = & $GetPageItemCount $Page
        Write-Action1Debug "[$Label] Processing page $PageNumber. Items: $ItemCount"

        foreach ($Item in @($Page.items)) {
            $Item
        }
    }
}

function Add-Action1PolicyResultDetailsMethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$InputObject
    )

    begin {
        $GetDetailsScriptBlock = {
            Invoke-Action1PagedGetRequest -Path $this.details -Label 'PolicyResultsDetails'
        }
    }
    process {
        $InputObject | Add-Member -MemberType ScriptMethod -Name 'GetDetails' -Value $GetDetailsScriptBlock -Force
        $InputObject
    }
}

function Add-Action1EndpointCustomAttributeMethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$InputObject
    )

    begin {
        $GetCustomAttributeScriptBlock = {
            param(
                [Parameter(Mandatory)]
                [string]$Name
            )
            ($this.custom | Where-Object { $_.name -eq $Name }).value
        }
    }
    process {
        $InputObject | Add-Member -MemberType ScriptMethod -Name 'GetCustomAttribute' -Value $GetCustomAttributeScriptBlock -Force
        $InputObject
    }
}



function Write-Action1Debug {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowEmptyString()]
        [string]$Message
    )

    if (-not $Script:Action1_DebugEnabled) {
        return
    }

    Write-Host ("Action1 Debug: {0}" -f $Message) -ForegroundColor Blue
}





function Resolve-Action1OrganizationByName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Org_Name
    )

    $organizations = @(Get-Action1 -Query Organizations -ErrorAction Stop)

    $matches = @(
        $organizations | Where-Object {
            $_.name -ieq $Org_Name
        }
    )

    if ($matches.Count -eq 0) {
        Write-Error "Organization with name '$Org_Name' was not found." -ErrorAction Stop
    }

    if ($matches.Count -gt 1) {
        $matchDetails = ($matches | ForEach-Object {
            "$($_.name) [$($_.id)]"
        }) -join ', '

        Write-Error "Organization name '$Org_Name' is not unique. Matching organizations: $matchDetails. Use -Org_ID with the exact organization ID." -ErrorAction Stop
    }

    return $matches[0]
}















