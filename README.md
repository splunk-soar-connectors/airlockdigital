[comment]: # "Auto-generated SOAR connector documentation"
# Airlock Digital

Publisher: Domenico Perre & Airlock Digital Pty Ltd  
Connector Version: 2\.0\.0  
Product Vendor: Airlock  
Product Name: Airlock Digital  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.3\.3  

This app provides investigative, containment, and management actions for Airlock Digital's Execution Control & Allow listing endpoint product

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Airlock Digital asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**apiKey** |  required  | password | Airlock API Key
**base\_url** |  required  | string | Airlock Digital REST API URL

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[unblock hash](#action-unblock-hash) - Unblock \(remove\) hashes from one or more Blocklist policies  
[disallow hash](#action-disallow-hash) - Disallow \(remove\) hashes from one or more Application Captures  
[list identifiers](#action-list-identifiers) - Gathers a list of identifiers which are required for referencing groups, applications, baselines, or blocklists in other actions  
[list policy](#action-list-policy) - List the policy configuration of a specified group  
[move endpoint](#action-move-endpoint) - Moves an endpoint from one group to another  
[allow hash](#action-allow-hash) - Allow \(add\) hashes in an Application Capture policy  
[block hash](#action-block-hash) - Block \(add\) hashes in a Blocklist policy  
[list endpoints](#action-list-endpoints) - List all the registered agents  
[revoke otp](#action-revoke-otp) - Revoke the One Time Password  
[retrieve otp](#action-retrieve-otp) - Retrieve the One Time Password  
[lookup hash](#action-lookup-hash) - Lookup SHA256 hash  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

This endpoint will test connectivity with an Airlock Digital server\.

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'unblock hash'
Unblock \(remove\) hashes from one or more Blocklist policies

Type: **correct**  
Read only: **False**

This action will unblock hashes from one or more Blocklist policies\. This is useful if you want to 'un\-ban' a particular hash value\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash\(SHA256\) of file\(s\) to unblock | string |  `sha256` 
**blocklistid** |  optional  | Remove hash\(es\) from a specific blocklist by specifying the ID, or leave this blank to remove it from all blocklists | string |  `airlockdigital blocklistid` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.blocklistid | string |  `airlockdigital blocklistid` 
action\_result\.parameter\.hash | string |  `sha256` 
action\_result\.data\.error | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'disallow hash'
Disallow \(remove\) hashes from one or more Application Captures

Type: **contain**  
Read only: **False**

This action will allow you to remove hashes for an existing Application Capture that exists on the Airlock Server\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash\(SHA256\) of file\(s\) to disallow | string |  `sha256` 
**applicationid** |  optional  | Remove hash\(es\) from a specific Application Capture by specifying the ID, or leave this blank to remove it from all Application Captures | string |  `airlockdigital applicationid` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.applicationid | string |  `airlockdigital applicationid` 
action\_result\.parameter\.hash | string |  `sha256` 
action\_result\.data\.error | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list identifiers'
Gathers a list of identifiers which are required for referencing groups, applications, baselines, or blocklists in other actions

Type: **investigate**  
Read only: **True**

This action gathers the identifiers which reference the groups, applications, baselines, or blocklists within Airlock\. These identifiers are required to call other actions within the Phantom in order to interact with the Airlock Server\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**policy\_type** |  required  | The type can be group, application, baseline, or blocklist | string |  `airlockdigital policytype` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.policy\_type | string |  `airlockdigital policytype` 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.parent | string | 
action\_result\.data\.\*\.type | string |  `airlockdigital policytype` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list policy'
List the policy configuration of a specified group

Type: **investigate**  
Read only: **True**

This action will return the policy configurations that are applied to the specified group, the group in this action is referenced by the Group ID\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group\_id** |  required  | The Group ID of the group you want to retrieve policy configuration from | string |  `airlockdigital groupid` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.group\_id | string |  `airlockdigital groupid` 
action\_result\.data\.\*\.response\.agentstopcode | string | 
action\_result\.data\.\*\.response\.applications\.\*\.applicationid | string |  `airlockdigital applicationid` 
action\_result\.data\.\*\.response\.applications\.\*\.name | string | 
action\_result\.data\.\*\.response\.auditmode | numeric | 
action\_result\.data\.\*\.response\.baselines\.\*\.baselineid | string | 
action\_result\.data\.\*\.response\.baselines\.\*\.name | string | 
action\_result\.data\.\*\.response\.batch | numeric | 
action\_result\.data\.\*\.response\.blocklists\.\*\.blocklistid | string |  `airlockdigital blocklistid` 
action\_result\.data\.\*\.response\.blocklists\.\*\.name | string | 
action\_result\.data\.\*\.response\.command | numeric | 
action\_result\.data\.\*\.response\.commlist\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.response\.commlist\.\*\.name | string | 
action\_result\.data\.\*\.response\.commlistid | string | 
action\_result\.data\.\*\.response\.enable\_notifications | numeric | 
action\_result\.data\.\*\.response\.groupid | string |  `airlockdigital groupid` 
action\_result\.data\.\*\.response\.hashdb\_ver | numeric | 
action\_result\.data\.\*\.response\.htmlapplication | numeric | 
action\_result\.data\.\*\.response\.javaapplication | numeric | 
action\_result\.data\.\*\.response\.javascript | numeric | 
action\_result\.data\.\*\.response\.name | string | 
action\_result\.data\.\*\.response\.notification\_message | string | 
action\_result\.data\.\*\.response\.parent | string | 
action\_result\.data\.\*\.response\.paths\.\*\.name | string | 
action\_result\.data\.\*\.response\.policyver | numeric | 
action\_result\.data\.\*\.response\.poll\_time | numeric | 
action\_result\.data\.\*\.response\.powershell | numeric | 
action\_result\.data\.\*\.response\.proxyauth | numeric | 
action\_result\.data\.\*\.response\.proxyenabled | numeric | 
action\_result\.data\.\*\.response\.proxypass | string | 
action\_result\.data\.\*\.response\.proxyport | string | 
action\_result\.data\.\*\.response\.proxyserver | string | 
action\_result\.data\.\*\.response\.proxyuser | string |  `user name` 
action\_result\.data\.\*\.response\.pslockdown | numeric | 
action\_result\.data\.\*\.response\.publishers\.\*\.name | string | 
action\_result\.data\.\*\.response\.python | numeric | 
action\_result\.data\.\*\.response\.script\_enabled | numeric | 
action\_result\.data\.\*\.response\.trusted\_upload | numeric | 
action\_result\.data\.\*\.response\.vbscript | numeric | 
action\_result\.data\.\*\.response\.windowsinstaller | numeric | 
action\_result\.data\.\*\.response\.windowsscriptcomponent | numeric | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'move endpoint'
Moves an endpoint from one group to another

Type: **generic**  
Read only: **False**

This action moves an enforcement agent registration from one group within Airlock to another\. This requires the destination Group ID to be referenced in the request as the 'target'\. The source group does not need to be specified\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group\_id** |  required  | A destination Group ID can be obtained from the list identifiers endpoint | string |  `airlockdigital groupid` 
**agent\_id** |  required  | Agent ID can be obtained from the list endpoints action | string |  `airlockdigital agentid` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.agent\_id | string |  `airlockdigital agentid` 
action\_result\.parameter\.group\_id | string |  `airlockdigital groupid` 
action\_result\.data\.error | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'allow hash'
Allow \(add\) hashes in an Application Capture policy

Type: **correct**  
Read only: **False**

This endpoint allows for the submission of a SHA256 hash value into an existing Application Capture policy\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash\(SHA256\) of file\(s\) to allow in an Application Capture | string |  `sha256` 
**applicationid** |  required  | Allow hash\(es\) in a specific Application Capture by specifying the ID | string |  `airlockdigital applicationid` 
**path** |  required  | Specify a file path that represents the hash of the file you are adding\. If you don't want to do this, use the default however this parameter is required for the population of file repository entries in Airlock\. Note that the path must be escaped | string |  `file path` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.applicationid | string |  `airlockdigital applicationid` 
action\_result\.parameter\.hash | string |  `sha256` 
action\_result\.parameter\.path | string |  `file path` 
action\_result\.data\.error | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'block hash'
Block \(add\) hashes in a Blocklist policy

Type: **contain**  
Read only: **False**

This action allows you to add hashes to a Blocklist policy\. By adding a hash into a Blocklist policy that is approved, it has the result of blocking the hash on endpoints within your environment\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash\(SHA256\) of file\(s\) to ban/block | string |  `sha256` 
**blocklistid** |  required  | Blocklist ID | string |  `airlockdigital blocklistid` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.blocklistid | string |  `airlockdigital blocklistid` 
action\_result\.parameter\.hash | string |  `sha256` 
action\_result\.data\.error | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list endpoints'
List all the registered agents

Type: **investigate**  
Read only: **True**

This endpoint will simply return a listing of registered agents from the Airlock Server\. This list can be filtered based on certain criteria\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hostname** |  optional  | Host Name | string |  `host name` 
**domain** |  optional  | Domain Name | string |  `domain` 
**ip** |  optional  | IP Address | string |  `ip` 
**username** |  optional  | Username | string |  `user name` 
**status** |  optional  | Status of device | numeric |  `airlockdigital devicestatus` 
**agentid** |  optional  | Agent ID | string |  `airlockdigital agentid` 
**groupid** |  optional  | Group ID | string |  `airlockdigital groupid` 
**os** |  optional  | Operating System | string |  `airlockdigital operatingsystem` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.agentid | string |  `airlockdigital agentid` 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.parameter\.groupid | string |  `airlockdigital groupid` 
action\_result\.parameter\.hostname | string |  `host name` 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.os | string |  `airlockdigital operatingsystem` 
action\_result\.parameter\.status | numeric |  `airlockdigital devicestatus` 
action\_result\.parameter\.username | string |  `user name` 
action\_result\.data\.\*\.agentid | string |  `airlockdigital agentid` 
action\_result\.data\.\*\.clientversion | string | 
action\_result\.data\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.freespace | string | 
action\_result\.data\.\*\.groupid | string |  `airlockdigital groupid` 
action\_result\.data\.\*\.hostname | string |  `host name` 
action\_result\.data\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.os | string |  `airlockdigital operatingsystem` 
action\_result\.data\.\*\.policyversion | string | 
action\_result\.data\.\*\.status | numeric |  `airlockdigital devicestatus` 
action\_result\.data\.\*\.username | string |  `user name` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'revoke otp'
Revoke the One Time Password

Type: **generic**  
Read only: **False**

Revoke an active OTP code by specifying the 'otpid' you want to revoke\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**otpid** |  required  | The ID of the OTP Code you want to revoke | string |  `airlockdigital otpid` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.otpid | string |  `airlockdigital otpid` 
action\_result\.data\.error | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'retrieve otp'
Retrieve the One Time Password

Type: **generic**  
Read only: **False**

Retrieve an OTP code for a particular computer \(agent\) within Airlock\. You must specify the OTP 'duration' and unique 'agentid' to retrieve the code\. Unique 'agentid' parameters can be obtained from the /agent/find endpoint\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**agentid** |  required  | Agent ID can be found using /agent/find, this will be the unique ID of a computer | string |  `airlockdigital agentid` 
**purpose** |  required  | Purpose of requesting the OTP Code | string |  `airlockdigital otpreason` 
**duration** |  required  | Duration of OTP Code | string |  `airlockdigital otpduration` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.agentid | string |  `airlockdigital agentid` 
action\_result\.parameter\.duration | string |  `airlockdigital otpduration` 
action\_result\.parameter\.purpose | string |  `airlockdigital otpreason` 
action\_result\.data\.\*\.response\.otpcode | string | 
action\_result\.data\.\*\.response\.otpid | string |  `airlockdigital otpid` 
action\_result\.data\.error | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup hash'
Lookup SHA256 hash

Type: **investigate**  
Read only: **True**

Query the Airlock file repository by specifying the hash value\(s\) you would like to lookup\. NOTE\: Only SHA256 hashes are supported\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash\(SHA256\) to lookup | string |  `sha256` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `sha256` 
action\_result\.data\.\*\.response\.results\.\*\.data\.createtime | string | 
action\_result\.data\.\*\.response\.results\.\*\.data\.datetime | string | 
action\_result\.data\.\*\.response\.results\.\*\.data\.description | string | 
action\_result\.data\.\*\.response\.results\.\*\.data\.filename | string |  `file name` 
action\_result\.data\.\*\.response\.results\.\*\.data\.filepath | string |  `file path` 
action\_result\.data\.\*\.response\.results\.\*\.data\.filesize | string |  `file size` 
action\_result\.data\.\*\.response\.results\.\*\.data\.md5 | string |  `md5` 
action\_result\.data\.\*\.response\.results\.\*\.data\.modtime | string | 
action\_result\.data\.\*\.response\.results\.\*\.data\.origname | string |  `file name` 
action\_result\.data\.\*\.response\.results\.\*\.data\.productname | string | 
action\_result\.data\.\*\.response\.results\.\*\.data\.productversion | string | 
action\_result\.data\.\*\.response\.results\.\*\.data\.publisher | string | 
action\_result\.data\.\*\.response\.results\.\*\.data\.reputation\.lastseen | string | 
action\_result\.data\.\*\.response\.results\.\*\.data\.reputation\.scannercount | string | 
action\_result\.data\.\*\.response\.results\.\*\.data\.reputation\.scannermatch | string | 
action\_result\.data\.\*\.response\.results\.\*\.data\.reputation\.status | string | 
action\_result\.data\.\*\.response\.results\.\*\.data\.reputation\.threatlevel | string | 
action\_result\.data\.\*\.response\.results\.\*\.data\.reputation\.threatname | string | 
action\_result\.data\.\*\.response\.results\.\*\.data\.reputation\.timestamp | string | 
action\_result\.data\.\*\.response\.results\.\*\.data\.sha128 | string | 
action\_result\.data\.\*\.response\.results\.\*\.data\.sha384 | string | 
action\_result\.data\.\*\.response\.results\.\*\.data\.sha512 | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 