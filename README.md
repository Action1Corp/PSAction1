![_Company_Logo](https://www.action1.com/wp-content/uploads/2022/02/action1-logo.svg)
**Patch Management That Just Works**
  
[**First 200 endpoints are free, fully featured, forever.**](https://www.action1.com/free)
***
# PSAction1 - PowerShell interface to the Action1 API

:stop_sign: **IMPORTANT, READ CAREFULLY!** _The module provided and outlined here along with examples are for an convenience. Though care has been taken to provide proper function and no adverse effects, each environment can be different. Carefully read, understand, and test before using in production, executing it on a test environment first. It is the responsibility of you, the user, to ensure all use function behaves as expected and creates no adverse conditions. Your use implies you have read and accept these conditions._

## Install from PowerShell Gallery
Once installed from the PowerShell gallery, this module will remain resident and does not have to be explicitly imported on each execution.
```PowerShell

PS C:\> Install-Module PSAction1

```

## Install manually

If you would prefer to review the code prior to use you can download the module and put it manually in your `$PSModulePath`.  
Download it from here for the latest builds, or the [PowerShell Gallery](https://www.PowerShellgallery.com/packages/PSAction1) for the lastest stable release.
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


**You are now ready to get started, let's GO!** :tada:


## Using this module

The first order of operation is to set up authentication, if you do not supply these values beforehand, the script will error telling you what required value is missing. Alteratively if you would rather walk through it step by step, you can set the option **Set-Action1Interactive $true**. Authentication sessions have a timeout, but the module accounts for that. 

When PSAction1 stores the bearer token for you, it checks before use, and if necessary will renew it on demand. This does introduce a very small delay when this happens much like first use, but the impact is minimal and likely not even noticed if not explained. When debug is on, you will see this in process. So once authenticated, there is no furher authentication required for the duration of the session regardless of length.
  
:stop_sign: **Important:**  _These are example values and DO NOT belong to a live instance, substitute the values with those obtained from the instructions above._

```PowerShell
PS C:\> Set-Action1Region NorthAmerica # Choices are currently NorthAmerica and Europe, more coming soon.
PS C:\> Set-Action1Credentials -APIKey api-key-example_e0983b7c-45e8-4c82-9f98-b63bdc4dcb33@action1.com -Secret 652b47a18e212e695e9fbfaa

```
Next you will have to set an organization context.  
Each organization will have a unique ID, you can locate it in the url when you log into Action1.  
By default there is only one organization. If you are a Managed Service Provider (MSP) or an enterprise with multiple entities, you can create multiple organizations to separate their data from each other.  
  
https[]()://app.action1.com/console/dashboard?org=**88c8b425-871e-4ff6-9afc-00df8592c6db** <- This is your Org_ID

Like the APIKey and Secret, this value is remembered for the duration of the session, as well if not specified beforehand, you will be prompted when needed. If you wish to do something in the context of another organization, you need to sets the context before performing additional actions.  
  
:stop_sign: **Important:**  _You can only operate in the context of one organization at a time as all functions relate to a specific organization._

```PowerShell

PS C:\> Set-Action1DefaultOrg -Org_ID 88c8b425-871e-4ff6-9afc-00df8592c6db

```

### You are all set up, let's do something useful.

There are five main commands:
  - **Get-Action1**
    - Retrieves data only makes no changes to actual instance.
  - **New-Action1**
    - Creates items and returns the new object.
  - **Set-Action1[KeyWord]**
    - Sets values in module only, does not interact with server data directly.
  - **Update-Action1**
    - Used to modify or delete items.
  - **Start-Action1Requery**
    - Used to request the system do a refresh of data.

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
:left_speech_bubble: **Note:** _All endpoints have custom attributes that can be set via direct syntax per ID/Attribute._

```PowerShell

PS C:\>  Update-Action1 Modify CustomAttribute -Id 'ef17c844-5b7c-4b32-9724-f2716b596639' -AttributeName "Custom Attribute 1" -AttributeValue "test this"

```

 
### The list of additional query expressions:

  - Automations
  - AdvancedSettings
  - Apps
  - EndpointGroupMembers
  - EndpointGroups
  - Me
  - Endpoint
  - EndpointApps
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
  - RawURI
  - Settings

:left_speech_bubble: **Note:** _Notice here that some queries are plural some are singular, all that are plural return a collection of items of that type.  
  
The singular ones target an object by its **-Id** property , if the object is not found, the return will be NULL, and you will receive an error message indicating the specified ID could not be found. Also, notice here I did not specify **-Query**, as it is the first bound param, it can be implied._

This returns the same object as above, directly without having to pull all objects and search, which is multifold more efficient.  

```PowerShell

PS C:\> Get-Action1 Endpoint -Id ef17c844-5b7c-4b32-9724-f2716b596639

```

Let's do more than just look, let's change something!

- I start by querying the groups, to find one with the name matching what we are looking for.  
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

:left_speech_bubble: **Note:** _When using **-Clone** it accepts an Id as a param, so it implies **-Id**_  

The syntax for modifying should come naturally when you know how to query and create but we do it with Update-Action1.  
  
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

Cloning is useful when you have an object that is mostly what you want and want to tweak for another purpose, but you _can_ start from scratch as well.
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

These helper methods are usually to manage group actions where more than one value is set at once,  handle object collections where multiple values must be set on one object and specific case/structure must be enforced, or perform bulk actions.

Examples of all three being as follows, using an Automation clone as an example.  
In this case we specify just the ID of the Endpoint or EndpointGroup as "Endpoint/EndpointGroup" is implied by the method name.  
The method ensures that the case sensitive attributes that are implied here, as well as the JSONs formating, are created properly using ID alone as a param.
Clear methods require no params as they imply an absolute action.  

:left_speech_bubble: **Note:** _When using Delete...() methods, the identifier used will be either the ID or the Name of the objet to be removed. This will vary in cases such as in EndpointGroups where 'Filters' are added by name, in Automations 'Endpoints/EndpointGroups' are added by ID._

```PowerShell
PS C:\> $clone = get-Action1 Settings -For Automation -Clone PolicyStore_Do_this_thing_1699034505782
PS C:\> $clone.ClearEndpoints()                                        
PS C:\> $clone.AddEndpoint('ef17c844-5b7c-4b32-9724-f2716b596639')
PS C:\> $clone.AddEndpointGroup('Service_1696554367754')               
PS C:\> $clone

name          : Policy Store Do this thing
settings      : DISABLED
retry_minutes : 1440
endpoints     : {@{id=ef17c844-5b7c-4b32-9724-f2716b596639; type=Endpoint}, @{id=Service_1696554367754; type=EndpointGroup}}
actions       : {@{name=Run Command; template_id=run_script; params=; id=Run_Command_0d499d60-7a73-11ee-a574-3509a7afa959}}

PS C:\> $clone.DeleteEndpointGroup('Service_1696554367754')
PS C:\> $clone

name          : Policy Store Do this thing
settings      : DISABLED
retry_minutes : 1440
endpoints     : {@{id=ef17c844-5b7c-4b32-9724-f2716b596639; type=Endpoint}}
actions       : {@{name=Run Command; template_id=run_script; params=; id=Run_Command_0d499d60-7a73-11ee-a574-3509a7afa959}}
       
```

:left_speech_bubble: **Note:** _It is also both important and comforting to note here, that all of these these actions are being performed on an in memory object client side. None of these changes are actually committed to the server, until the object is passed as the **-Data** param to an execution of an **Update-Action1** or **New-Action1**. Changes made here can be made, reviewed, or discarded without commitment, with no adverse effects. So please do review and get familiar with how these helper methods work before committing them to the server. A good primer in their function will be to create an object in the Action1 console, and then pull that object into PSAction1. Look at how the data comes structured in the system, methods will format data following that pattern._

Then we could can delete an object, so let's target the clone we just made and pushed up.  
Delete operations prompt for confirmation by default, **-Force** overrides that behavior.

  :stop_sign: **Important:** _Deleting an object is irreversible. Use extreme scrutiny and caution when deleting, **ESPECIALLY** if utilizing the **-Force** option!_
  
```PowerShell
PS C:\> Update-Action1 Delete -Type Group -Id MyNewGroup_1702147189271 -Force 
```
### Deploying patches and software packages

As of version 1.3.8, you can now deploy both patches and software packages through PSAction1! Like many of the other actions, it starts by getting a settings template for the operation, adding relevant information about what you would like to deploy, and then creating a new object in Action1 to kick it off. In this case the type of object created is a policy instance. This is a special type of automation that runs once on demand and does not leave a template in the automations section inside Action1, but it can still be found in the history of any endpoint that it was assigned to.

Let’s look at an example of issuing a remediation to an endpoint for a particular vulnerability. When patching a vulnerability, it is identified by its CVS id, so we start by getting a Remediation settings template, adding one or more CVE’s to be addressed to it, assigning it to one or more endpoint groups, and then push it back to the server.

:left_speech_bubble: **Note:** _It is not only likely, it is common, that a single patch will address multiple CVEs in one install. PSAction1 will intelligently address this by detecting that the patch for any given CVE is already added to the queue if you attempt to add additional CVEs from the same patch. This allows you to add all CVEs you wish to address, and the resulting patch list will resolve itself. However, note as well, that all CVEs addressed by that patch will be covered, not **just** the one you added._

```Powershell
PS C:\> $push = Get-Action1 Settings -For Remediation
PS C:\> $push.AddCVE('CVE-2022-3775')
PS C:\> $push.AddEndpointGroup('Test_1720748341834')
PS C:\> New-Action1 Remediation -Data $push
```
Software packages get deployed in much the same way, they just require a package id, the script will automatically select the correct version as being the latest available for the package requested. Like remediation, the queue can have one or more packages added, and will prevent you from adding the same package twice. Also, there are helper methods to add endpoints and endpoint groups. So, we create a template object, add a software package, add endpoints and then create a new policy instance object in Action1. Like a remediation this special type of automation will show in the endpoint automation history, but not the Automation section in the Action1 console.

```Powershell
PS C:\> $data = Get-Action1 Settings -For DeploySoftware
PS C:\> $data.AddEndpoint('bfbd1da2-d746-44dc-9c87-89382bbd4c53')
PS C:\> $data.AddPackage('Martin_P_ikryl_WinSCP_1632062504985_builtin')   #ID of package from Get-Action1 Packages
PS C:\> New-Action1 DeploySoftware -Data $data 
```

### Reporting

You can pull report data as well through PSAction1, reports an be retrieved as objects for property manipulation, such as ...

```PowerShell
PS C:\> Get-Action1 ReportData -Id 'installed_software_1635264799139'

id              : ZDesigner%2520Windows%2520Printer%2520Driver%2520Version                                                                                                                                        type            : ReportRow                                                                                                                                                                                       self            : https://app.action1.com/api/3.0/reportdata/df137c59-f12a-03c6-7b7e-63701cb6eba3/installed_software_1635264799139/data/ZDesigner%2520Windows%2520Printer%2520Driver%2520Version                  
fields          : @{Name=ZDesigner Windows Printer Driver Version; Details=2}
drilldown_field : Details
drilldown       : https://app.action1.com/api/3.0/reportdata/df137c59-f12a-03c6-7b7e-63701cb6eba3/installed_software_1635264799139/data/ZDesigner%2520Windows%2520Printer%2520Driver%2520Version/drilldown        

id              : Zebra%2520Font%2520Downloader
type            : ReportRow
self            : https://app.action1.com/api/3.0/reportdata/df137c59-f12a-03c6-7b7e-63701cb6eba3/installed_software_1635264799139/data/Zebra%2520Font%2520Downloader
fields          : @{Name=Zebra Font Downloader; Details=1}
drilldown_field : Details
drilldown       : https://app.action1.com/api/3.0/reportdata/df137c59-f12a-03c6-7b7e-63701cb6eba3/installed_software_1635264799139/data/Zebra%2520Font%2520Downloader/drilldown

...
```
This retrieves an object collection with the id and other details of each of your report objects. Mostly this is useful for determining the id of a particular report you would like to retrieve data for. 

Then you can use that id to pull the actual data in CSV format for integration with or consumption by other systems.

```PowerShell
PS C:\> Get-Action1 ReportExport -Id 'installed_software_1635264799139'

Name,Details
ZDesigner Windows Printer Driver Version,2
Zebra Font Downloader,1

...
```

Last but not least, is that because report data is polled, there is a chance when you check at any instant all data will not be up to the minute current.

```PowerShell
PS C:\> Start-Action1Requery -Type InstalledSoftware 
PS C:\> Start-Action1Requery -Type InstalledSoftware -Endpoint_Id 'ef17c844-5b7c-4b32-9724-f2716b596639'
```

These statements are non-blocking, meaning they initiate a re-query of the data, but the re-query is not instantaneous and can vary depending on your particular deployment. Therefore an immediate attempt to export data again may or may not contain the complete information set from this request. After a reasonable period however it should improve the accuracy of the reported data for all endpoints that are reachable. In the case of **ReportData** and **InstalledSoftware**, these re-query actions can be made as granular as the endpoint, however in the case of **InstaledUpdates** it is only system wide.  

:left_speech_bubble: **Note:** _When this request it made it will be honored the next time an endpoint is visible, it has no affect on offline endpoints until they reconnect.._

### Extending / testing / playground

This interface is not exhaustive, it used the most commonly requested features of the API, but the API is far larger and feature rich than represented here. That said, the PSAction1 module can still assist. You can use the authentication mechanism to run custom URIs for the purpose of rapidly exploring the API or extending it for more function. To do this the PSAction1 module contains a RawURI method in Get-Action1.

```PowerShell

PS C:\> Get-Action1 RawURI -URI https://app.action1.com/api/3.0/policies/schedules/88c8b425-871e-4ff6-9afc-00df8592c6db/PolicyStore_Do_this_thing_1699034505782

```

### Troubleshooting

 At any time you can enable and disable debug to get more information about what is occurring "under the hood", and what is being exchanged with the server. This is especially useful when looking at JSON POST/PATCH data going to the server.

```PowerShell
PS C:\> Set-Action1Debug $true
  Action1 Debug: Debugging enabled.
PS C:\> Set-Action1Debug $false
```

### And you can always reach out to myself or the community directly on our [Discord](https://discord.com/channels/841428478669881356/841428479266258946) server or our [Reddit](https://www.reddit.com/r/Action1/) sub.

## WARNING: Carefully study the provided scripts and components before using them. Test in your non-production lab first.

LIMITATION OF LIABILITY. IN NO EVENT SHALL ACTION1 OR ITS SUPPLIERS, OR THEIR RESPECTIVE OFFICERS, DIRECTORS, EMPLOYEES, OR AGENTS BE LIABLE WITH RESPECT TO THE WEBSITE OR THE COMPONENTS OR THE SERVICES UNDER ANY CONTRACT, NEGLIGENCE, TORT, STRICT LIABILITY OR OTHER LEGAL OR EQUITABLE THEORY (I)FOR ANY AMOUNT IN THE AGGREGATE IN EXCESS OF THE GREATER OF FEES PAID BY YOU THEREFOR OR $100; (II) FOR ANY INDIRECT, INCIDENTAL, PUNITIVE, OR CONSEQUENTIAL DAMAGES OF ANY KIND WHATSOEVER; (III) FOR DATA LOSS OR COST OF PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; OR (IV) FOR ANY MATTER BEYOND ’S REASONABLE CONTROL. SOME STATES DO NOT ALLOW THE EXCLUSION OR LIMITATION OF INCIDENTAL OR CONSEQUENTIAL DAMAGES, SO THE ABOVE LIMITATIONS AND EXCLUSIONS MAY NOT APPLY TO YOU.
