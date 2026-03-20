---
external help file: PSAction1-help.xml
Module Name: PSAction1
online version:
schema: 2.0.0
---

# about_Action1

![_Company_Logo](https://www.action1.com/wp-content/uploads/2022/02/action1-logo.svg)

**Patch Management That Just Works**

[**First 200 endpoints are free, fully featured, forever.**](https://www.action1.com/free)

## SHORT DESCRIPTION

Provides PowerShell access to the Action1 API for managing endpoints, automations, and configurations.

## LONG DESCRIPTION

The Action1 module allows administrators to interact with the Action1 platform using PowerShell.

It provides capabilities to:

* Authenticate using API credentials
* Query endpoints, reports, and configurations
* Create and manage automations and endpoint groups
* Trigger data re-queries
* Upload and deploy software packages

The module is suitable for both interactive usage and automation scenarios.

```powershell
Set-Action1Interactive -Enabled $true
```

---

## GETTING STARTED

Before using the module, configure authentication.

### Step 1: Set credentials

```powershell
Set-Action1Credentials -APIKey "your-api-key" -Secret "your-secret"
```

### Step 2:  Set region

```powershell
Set-Action1Region -Region "NorthAmerica"
```

### Step 3: Specify organization to work with

```powershell
Set-Action1DefaultOrg -Org_ID "org-12345"
```

### Step 4: Verify access

```powershell
Get-Action1 -Query Me
```

## BASIC WORKFLOW

Typical usage flow:

* Authenticate → Set-Action1Credentials

* Configure → Set-Action1Region, Set-Action1DefaultOrg

* Query data → Get-Action1

* Create resources → New-Action1

* Modify resources → Update-Action1

* Refresh data → Start-Action1Requery

* Deploy software → Start-Action1PackageUpload

## COMMANDS

### Set-Action1Credentials

Sets API credentials for the current session.

```powershell
Set-Action1Credentials -APIKey <String> -Secret <String>
```

Stores credentials used by all module commands.

### Set-Action1DefaultOrg

Sets the Action1 organization.

```powershell
Set-Action1DefaultOrg -Org_ID "org-12345"
```

Configures Action1 organization to interact with.

### Set-Action1Region

Sets the Action1 API region.


```powershell
Set-Action1Region -Region <String>
```

Configures which regional Action1 API endpoint to use.

### Get-Action1

Retrieves data from the Action1 API.


```powershell
Get-Action1 -Query <String>
```

Supports retrieving:

  *  Endpoints

  *  Automations

  *  Reports

  *  Installed software

  * Current user information

### New-Action1

Creates new objects.

```powershell
New-Action1 -Item <String> -Data <Object>
```

Used to create:

  *  Automations

  *  Endpoint groups

  *  Organizations

### Update-Action1

Modifies or deletes existing objects.


```powershell
Update-Action1 -Action <String> -Type <String> -Data <Object>
```

Supported actions:

  * Modify

  *  ModifyMembers

  * Delete

### Start-Action1Requery

Triggers data refresh on endpoints.


```powershell
Start-Action1Requery -Type <String> -Endpoint_Id <String>
```

Refreshes:

Installed software

Installed updates

Report data

### Start-Action1PackageUpload

Uploads and deploys software packages.

Handles package upload and deployment workflows.

## EXAMPLES

### Example 1: Retrieve endpoints

```powershell
Set-Credentials -APIKey "xxx" -Secret "yyy"

Get-Action1 -Query Endpoints
```

### Example 2: Create automation

```powershell
$data = @{
    name = "My Automation"
    description = "Example automation"
}

New-Action1 -Item Automation -Data $data
```

### Example 3: Update object

```powershell
Update-Action1 -Action Modify -Type EndpointGroup -Data $data
```

### Example 4: Trigger requery


```powershell
Start-Action1Requery -Type InstalledSoftware -Endpoint_Id "12345"
```

### Example 5: Full workflow

```powershell
Set-Action1Credentials -APIKey "xxx" -Secret "yyy"

Set-Action1Region -Region "eu"

$endpoints = Get-Action1 -Item Endpoints

$data = @{
    name = "Automation from PowerShell"
}

New-Action1 -Item Automation -Data $data
```

## AUTHENTICATION

All API operations require authentication.

Use **Set-Action1Credentials** to provide API key and secret.

Credentials are stored in memory and must be re-entered for each new PowerShell session.

## NOTES

Internet access is required

API permissions may limit available operations

Credentials are stored only for the duration of the session

## RELATED LINKS

[Get-Action1](Get-Action1.md)

[New-Action1](New-Action1.md)

[Update-Action1](Update-Action1.md)

[Set-Action1Credentials](Set-Action1Credentials.md)

[Set-Action1DefaultOrg](Set-Action1DefaultOrg.md)

[Start-Action1Requery](Start-Action1Requery.md)

[Start-Action1PackageUpload](Start-Action1PackageUpload.md)