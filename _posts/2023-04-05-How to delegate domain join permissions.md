---
title: "How to delegate domain join permissions - Using least privilege and best practice"
categories:
  - Windows
author:
 - Frederik Leed
tags:
  - Microsoft
  - Security
  - Powershell
  - ActiveDirectory
layout: post  
---

De-privileging the account(s) used for joining computers to the domain.

## What is the point?

Why do we need to use least-privilege permissions? In very simple words: **Cleaning up your permissions will help you be more resilient to attacks**

Way too often we see accounts used for domain join activities being member of higly privileged groups in Active Directory, like "Domain Admins" or "Administrators". These accounts are normally easy for an attacker, with access to corporate network, to compromise, since the account credentials are exposed during the OSDeployment process. (They have to be or they cannot be used).

One of the skilled consultants at [MicrosoftIR](https://aka.ms/MicrosoftIR) has created a great article about de-priviliging. You shoud give it a [read](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/why-de-privileging/ba-p/3779519).

Tips when creating new delegations for domian join!

 - Single use service accounts!
 - Single use passwords!
 - Use seperate accounts for servers and for workstations
 - If your Active Directory is tiered, use separate accounts for each tier
 - Delegate permissions to groups and not users directly. This makes reviewing AD permissions easier.


Here is quick sample of the core functionality of delegating domain join permissions. For a more extensive solution, keep reading!
## Isolated delegation function ![powershell](/assets/images/powershell.png){:width="30px"}

{% include codeHeader.html %}

```powershell
    $rootdse = Get-ADRootDSE
    $extendedrightsmap = @{} 
    Get-ADObject -SearchBase ($rootdse.ConfigurationNamingContext) -LDAPFilter "(&(objectclass=controlAccessRight)(rightsguid=*))" -Properties displayName,rightsGuid | ForEach-Object {$extendedrightsmap[$_.displayName]=[System.GUID]$_.rightsGuid}
    $spnguid = [System.Guid](Get-ADObject -Identity ("CN=Service-Principal-Name," + $rootdse.SchemaNamingContext) -Properties schemaIDGUID).schemaIDGUID
    $computerguid = [System.Guid](Get-ADObject -Identity ("CN=Computer," + $rootdse.SchemaNamingContext) -Properties schemaIDGUID).schemaIDGUID

function Set-DomainJoinPermissions($groupname, $ou){
    #http://support.microsoft.com/kb/932455
    # Create Computer Accounts
    # Delete Computer Accounts
    # Reset Password
    # Read and write Account Restrictions
    # Validated write to DNS host name 
    # Validated write to service principal name
    $groupsid = new-object System.Security.Principal.SecurityIdentifier (Get-ADGroup $groupname).SID

    $ace1 = new-object System.DirectoryServices.ActiveDirectoryAccessRule $groupsid,"CreateChild,DeleteChild","Allow",$computerguid
    $ace2 = new-object System.DirectoryServices.ActiveDirectoryAccessRule $groupsid,"ExtendedRight","Allow",$extendedrightsmap["Reset Password"],"Descendents",$computerguid
    $ace3 = new-object System.DirectoryServices.ActiveDirectoryAccessRule $groupsid,"readproperty,writeproperty","Allow",$extendedrightsmap["Account Restrictions"],"Descendents",$computerguid
    $ace4 = new-object System.DirectoryServices.ActiveDirectoryAccessRule $groupsid,"writeproperty","Allow",$extendedrightsmap["DNS Host Name Attributes"],"Descendents",$computerguid
    $ace5 = new-object System.DirectoryServices.ActiveDirectoryAccessRule $groupsid,"writeproperty","Allow",$spnguid,"Descendents",$computerguid
    $acl = Get-ACL -Path ("AD:\"+$ou)

    $acl.AddAccessRule($ace1)
    $acl.AddAccessRule($ace2)
    $acl.AddAccessRule($ace3)
    $acl.AddAccessRule($ace4)
    $acl.AddAccessRule($ace5)
    
    Set-ACL -ACLObject $acl -Path ("AD:\"+$ou)
}

Set-DomainJoinPermissions -groupname "DomainJoinGroup" -ou "OU=Workstations,DC=example,DC=com"
```

The above is an isolated simple function to do just one thing. To provide a more comprehensive solution, I have created a script and made it available in my Github repo.

The script performs the following tasks:

1. Creates a new service account with a specified name and path, and sets the password as provided by the user. (If an account with the specified name already exists, it will be used)
2. Creates a new security group with a specified name and path, and adds a description indicating the group's purpose. (If a group with the specified name already exists, it will be used)
3. Adds the service account to the security group.
4. Delegates the necessary permissions on the specified Organizational Unit (OU) to the security group, allowing its members to join machines to the domain.
5. Sets the ms-ds-MachineAccountQuota to 0 to prevent other users from joining machines to the domain.

The script includes error handling and logging to ensure smooth execution and provide useful information on the process.

Download [here](https://github.com/FrederikLeed/scripts-n-queries/blob/55bcb1699f9cbe62e8c38f5442c417eb5e2cdea2/ActiveDirectory/Delegate_domain_join.ps1)
