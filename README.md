![Action1_Company_Logo](https://www.action1.com/wp-content/uploads/2022/02/action1-logo.svg)
**Risk-Based Patch Manangement**
  
[**First 100 endpoints are free, fully featured, forever.**](https://www.action1.com/free)
***
# PSAction1 - PowerShell interface to the Action1 API

:stop_sign: **IMPORTANT, READ CAREFULLY!** _The module provided and outlined here along with examples are for an convenience. Though care has been taken to provide proper function and no adverse effects, each environment can be different. Carefully read, understand, and test before using in production, executing it on a test environment first. It is the responsibility of you, the user, to ensure all use function behaves as expected and creates no adverse conditions. Your use implies you have read and accept these conditions._
# Action1 Corporation holds no liability for any damages directly or indirectly caused by running these tools and samples.

## Install from PowerShell Gallery
Once installed from the PowerShell gallery, this module will remain resident and does not have to be explicitly imported on each execution.
```PowerShell

PS C:\> Install-Module PSAction1

```

## Install manually

If you would prefer to review the code prior to use you can download the module and put it manually in your `$PSModulePath`.  
Download it from here for the latest builds, or the [PowerShell Gallery](https://www.PowerShellgallery.com/packages/PSAction1) for the lastest stabile release.
Then import it into your script's session, this will need to be done on each execution of your script, so it is advised to make this the first line of the script before any other code.  
  
:stop_sign: **Important:**  _Code downloaded here will be in active development, for maximum stability you should use the module from the PowerShell gallery. You should only use the latest build from Git if you are instructed to do so by support, curious, troubleshooting a specific issue, or just the curious sort of person._
```PowerShell

PS C:\> Import-Module PSAction1

```

## Getting started

Before you begin, you will need to understand the basics of how to authenticate to the Action1 API.  
The getting started guide can be found here.  
[https://www.action1.com/api-documentation](https://www.action1.com/api-documentation/api-credentials/)

Once you have followed the instructions to obtain an API key, you should have an "APIKey" (Client ID) value and "Secret" (Client Secret) value.


**You are now ready to get started, lets GO!** :tada:


## Using this module

The first order of operation is to set up authentication, if you do not supply these values beforehand, you will be prompted for them when needed.  
  
:stop_sign: **Important:**  _These are example values and DO NOT belong to a live instance, substitute the values with those obtained from the instructions above._

```PowerShell

PS C:\> Set-Action1Credentials -APIKey api-key-example_e0983b7c-45e8-4c82-9f98-b63bdc4dcb33@action1.com -Secret 652b47a18e212e695e9fbfaa

```
Next you will have to set an organization context.  
Each orgnization will have a uniqe ID, you can locate it in the url when you log into Action1.  
By default there is only one organization. If you are a Managed Service Provider (MSP) or an enterprise with multiple entities, you can create multiple organizations to separate their data from each other.  
  
https[]()://app.action1.com/console/dashboard?org=**88c8b425-871e-4ff6-9afc-00df8592c6db** <- This is your Org_ID

Like the APIKey and Secret, this value is remembered for the duration of the session, as well if not specified beforehand, you will be prompted when needed. If you wish to do something in the context of another organization, you need to sets the context before performing additonal actions.  
  
:stop_sign: **Important:**  _You can only operate in the context of one organization at a time as all functions relate to a specific organization._

```PowerShell

PS C:\> Set-Action1DefaultOrg -Org_ID 88c8b425-871e-4ff6-9afc-00df8592c6db

```

### You are all set up, let's do somehtign usefull.

There are four main commands:
  - **Get-Action1**
    - Retrieves data only makes no changes to actual instance.
  - **New-Action1**
    - Creates items and returns the new object.
  - **Set-Action1**
    - Sets values in module only, does not interact with server data directly.
  - **Update-Action1**
    - Used to modify or delete items.

Let's start by querying endpoints.

```PowerShell

PS C:\> Get-Action1 -Query Endpoints | select -First 1

id                   : ef17c844-5b7c-4b32-9724-f2716b596639
type                 : Endpoint
self                 : https://app.action1.com/api/3.0/endpoints/managed/88c8b425-871e-4ff6-9afc-00df8592c6db/ef17c844-5b7c-4b32-9724-f2716b596639/general
status               : Connected
last_seen            : 2023-12-09_01-44-11
name                 : A1DEV
address              : 192.168.0.135
OS                   : Windows 11 (23H2)
platform             : Windows_64
agent_version        : 5.179.579.1
agent_install_date   : 2023-11-08_19-11-15
subscription_status  : Active
user                 : A1DEV\gmoody
comment              : None
device_name          :
MAC                  : 08:00:27:60:A8:9D
serial               : 0
reboot_required      : No
online_status        : UNDEFINED
AD_organization_unit :
AD_security_groups   : {}
CPU_name             : Intel(R) Core(TM) i7-1065G7 CPU @ 1.30GHz
CPU_size             : 1x1.5 GHz, 4/4 Cores
disk                 : 80Gb Generic
manufacturer         : innotek GmbH
NIC                  : Intel(R) PRO/1000 MT Desktop Adapter
video                : VirtualBox Graphics Adapter (WDDM), , 0Gb
WiFi                 :
RAM                  : 0Gb Unknown
last_boot_time       : 2023-12-08_22-12-38
update_status        : UNDEFINED
vulnerability_status : UNDEFINED

```

### The list of additional query expressions:

  - Automations
  - AdvancedSettings
  - EndpointGroupMembers
  - EndpointGroups
  - Me
  - Endpoint
  - Endpoints
  - MissingUpdates
  - Organizations
  - Packages
  - Policy
  - Policies
  - PolicyResults
  - ReportData
  - ReportExport
  - Reports
  - Scripts
  - AgentDepoyment
  - Vulnerabilities
  - Settings

:left_speech_bubble: **Note:** _Notice here that some queries are plural some are singular, all that are plural return a collection of items of that type.  
The singular ones target an object by its **-Id** property , if the object is not found, the return will be NULL, and you will receive an error message indicating the specified ID could not be found. Also, notice here I did to specify **-Query**, as query is the first bound param, it can be implied._

This returns the same object as above, directly without having to pull all objects and search, which is multifold more efficient.  
```PowerShell

PS C:\> Get-Action1 Endpoint -Id ef17c844-5b7c-4b32-9724-f2716b596639

```

Let's do more than just look, let's change somethign!

- I start by querying the groups, to find one with the name matching what we are lookign for.  
- Next I just verified the group object visually, this is not required and is just for demonstration.  
- Next I made a clone of that group object, this would duplicate the group into an editable template to push back for creation.  
- And again I just verify for demonstration.  
- I rename that object, and then create a new group based on that data.  
- The object is returned with the id and details of the newly created group.  

:left_speech_bubble: **Note:** _Not all objects support creation and or cloning, the module will inform you in these cases._

```PowerShell
PS C:\> $group = Get-Action1 EndpointGroups | ?{$_.name -eq 'Service'}
PS C:\> $group

id             : Service_1696554367754
type           : EndpointGroup
self           : https://app.action1.com/api/3.0/endpoints/groups/88c8b425-871e-4ff6-9afc-00df8592c6db/Service_1696554367754
name           : Service
description    :
include_filter :  {@{field_name=OS; field_value=Windows 10; mode=include}, @{field_name=name; field_value=A1DEV; mode=include}}
exclude_filter : {}
contents       : https://app.action1.com/api/3.0/endpoints/groups/88c8b425-871e-4ff6-9afc-00df8592c6db/Service_1696554367754/contents
uptime_alerts  : @{offline_alerts_enabled=no; offline_alerts_delay=10; online_alerts_enabled=no; user_ids_for_notification=System.Object[]}

PS C:\> $clone = Get-Action1 Settings -for EndpointGroup -Clone $group.id
PS C:\> $clone | Format-List

name           : Service
description    :
include_filter :  {@{field_name=OS; field_value=Windows 10; mode=include}, @{field_name=name; field_value=A1DEV; mode=include}}
exclude_filter : {}

PS C:\> $clone.name = "Some New Name"
PS C:\> $clone | Format-List

name           : Some New Name
description    :
include_filter :  {@{field_name=OS; field_value=Windows 10; mode=include}, @{field_name=name; field_value=A1DEV; mode=include}}
exclude_filter : {}

PS C:\> New-Action1 EndpointGroup -Data $clone

id             : Some_New_Name_1702095463270
type           : EndpointGroup
self           : https://app.action1.com/api/3.0/endpoints/groups/88c8b425-871e-4ff6-9afc-00df8592c6db/Some_New_Name_1702095463270
name           : Some New Name
description    :
include_filter :  {@{field_name=OS; field_value=Windows 10; mode=include}, @{field_name=name; field_value=A1DEV; mode=include}}
exclude_filter : {}
contents       : https://app.action1.com/api/3.0/endpoints/groups/88c8b425-871e-4ff6-9afc-00df8592c6db/Some_New_Name_1702095463270/contents

```
:left_speech_bubble: **Note:** _When using **-Clone** it accepts an Id as a parameter, so it implies **-Id**_  

The syntax for modifying shoud come naturally when you know how to query and create but we do it with Update-Action1.  
  
```PowerShell
PS C:\> $group = Get-Action1 EndpointGroups | ?{$_.name -eq 'Some New Name'}
PS C:\> $clone = Get-Action1 Settings -for EndpointGroup -Clone $group.id
PS C:\> $clone.name = "Some Other Name"
PS C:\> Update-Action1 Modify -Type EndpointGroup -Id $group.id -Data $clone

id             : Some_New_Name_1702095463270
type           : EndpointGroup
self           : https://app.action1.com/api/3.0/endpoints/groups/88c8b425-871e-4ff6-9afc-00df8592c6db/Some_New_Name_1702100718378
name           : Some Other Name
description    :
include_filter : {@{field_name=OS; field_value=Windows 10; mode=include}}
exclude_filter : {}
contents       : https://app.action1.com/api/3.0/endpoints/groups/88c8b425-871e-4ff6-9afc-00df8592c6db/Some_New_Name_1702100718378/contents

```

Cloning is useful when you have an object that is mostly what you want and want to tweak for another purpose, but you can start from scratch as well.
Both in Clones and New Settings, there are helper methods to add things like include/exclude filters.

```PowerShell
PS C:\> $NewGroup = Get-Action1 Settings -For EndpointGroup
PS C:\> $NewGroup | Format-List

name           :
description    :
include_filter : {}
exclude_filter : {}

C:\> $NewGroup.Splat("MyNewGroup","The group I just Created")

name       description              include_filter exclude_filter
----       -----------              -------------- --------------
MyNewGroup The group I just Created {}             {}

PS C:\> $NewGroup.AddIncludeFilter('name','A1DEV','include')
PS C:\> New-Action1 EndpointGroup -Data $NewGroup               

id             : MyNewGroup_1702147189271
type           : EndpointGroup
self           : https://app.action1.com/api/3.0/endpoints/groups/88c8b425-871e-4ff6-9afc-00df8592c6db/MyNewGroup_1702147189271
name           : MyNewGroup
description    : The group I just Created
include_filter : {@{field_value=A1DEV; field_name=name; mode=include}}
exclude_filter : {}
contents       : https://app.action1.com/api/3.0/endpoints/groups/88c8b425-871e-4ff6-9afc-00df8592c6db/MyNewGroup_1702147189271/contents

```
Then we could can delete an object, so let's target the clone we just made and pushed up.  
Delete operations prompt for confirmaiton by default, -Force overrides that behavior.

  :stop_sign: **Important:** _Deleting an object is irreversible. Use extreme scrutiny when deleting **ESPECIALLY** if utilizing the **-Force** option!_
```PowerShell
PS C:\> Update-Action1 Delete -Type Group -Id MyNewGroup_1702147189271 -Force 
```

### Troubleshooting
 At any time you can enable and disable debug to get more informaiton about what is occuring "under the hood", and what is being exchanged with the server. This is especially usefull when looking at JSON POST/PATCH data going to the server.

```PowerShell
PS C:\> Set-Action1Debug $true
  Action1 Debug: Debugging enabled.
PS C:\> Set-Action1Debug $false
```

And you can always reach out to me direclty on our [Discord](https://discord.com/channels/841428478669881356/841428479266258946) server or our [Reddit](https://www.reddit.com/r/Action1/) sub.
