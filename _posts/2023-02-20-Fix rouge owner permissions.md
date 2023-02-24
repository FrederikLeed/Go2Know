---
title: "About owner rights in Active Directory"
categories:
  - Active Directory
author:
 - Frederik Leed
tags:
  - Microsoft
  - Security
  - Powershell
layout: post
---

In Active Directory, the object owner refers to the user or group that has ownership of an object. This permission can be abused!

![Microsoft Active Directory](/assets/images/Microsoft_ActiveDirectory.png){:width="360px"}

<!-- TOC start -->
- [Active Directory object ownership](#active-directory-object-ownership)
- [How can object ownership be abused?](#how-can-object-ownership-be-abused)
- [Detect object ownership discrepancies](#detect-object-ownership-discrepancies)
- [Set owner rights on AD objects](#set-owner-rights-on-ad-objects)
  * [Scheduling script to prevent future deviances](#scheduling-script-to-prevent-future-deviances)
  * [Scheduled task creation](#scheduled-task-creation)
<!-- TOC end -->

## Active Directory object ownership

In Active Directory, the object owner refers to the user or group that has ownership of an object. The owner of a securable object (represented by the Owner SID field in the security descriptor) has the READ_CONTROL and WRITE_DAC rights implicitly granted.

**WRITE_DAC** is a powerfull right. WRITE_DAC: The right to modify the discretionary access control list (DACL) in the object's security descriptor.

**Discretionary Access Control List**

(DACL) An access control list that is controlled by the owner of an object and that specifies the access particular users or groups can have to the object.

By default, the user who creates an object in Active Directory is set as the owner of that object. However, ownership can be transferred to another user or group by changing the ownership of the object.

## How can object ownership be abused? ![Hacker](/assets/images/hacker-icon.png){:width="50px"}

An attack on Active Directory using owner permissions in Active Directory could involve an attacker gaining ownership of a high-privileged object, such as a domain controller, by compromising the account of the current owner.

- Example 1: Once the attacker gains ownership of the object, they can use their new permissions to reset the password of the object and thus be able to authenticate as that object. In case of a domain admin or a domain controller, that permission can be used to create or modify other objects within the directory, including user accounts, groups, and permissions, among others. With these new permissions, the attacker can gain elevated privileges and perform actions that are outside the scope of their normal privileges.

- Example 2: Even if an owner does not have write permission to a specific object, the owner is able to assign write permissions or any other permissions on a given object. (Example: Ability to read LAPS password or ability to reset password enabling sign-in as user or computer)

To prevent such attacks, it is important to regularly review and monitor the ownership and permissions of high-privileged objects within Active Directory, and to ensure that access to these objects is restricted only to authorized individuals.

## Detect object ownership discrepancies

In Active Directory, securing some assets are of higher priority due to extended permissionsets. These assets include but are not limited to Built-In administrator and operator groups and members, Domain controller objects, other computer objects like AADConnect, ADFS, ADCS.

Here we have written a few lines of powershell to report on privilged AD Objects where Owner does not match "Domain Admins". There is a mention about AD tiering in the script, read about it [here](https://petri.com/use-microsofts-active-directory-tier-administrative-model/)

{% include codeHeader.html %}

```powershell
$AdminGroups = @"
Account Operators
Administrators
Backup Operators
Cert Publishers
DNSAdmins
Domain Admins
Enterprise Admins
Enterprise Key Admins
Key Admins
Print Operators
Replicator
Schema Admins
Server Operators
"@

#Modify this to match your environment
$PrivilegedServers = @"
adfs01
adfs02
ca01
ca02
aadc01
aadc02
"@

$Privilegedgroups = $AdminGroups.Split([System.Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries) | % {
    Get-ADGroup $_
}

$PrivilegedGroupMembers = $AdminGroups.Split([System.Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries) | % {
    Get-ADGroupMember $_ -Recursive
}

$PrivilegedServerObjects = $privilegedservers.Split([System.Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries) | % {
    Get-ADComputer $_
}

#If AD tiering is applied, looping through all objects within tier0 would be advised.
$ObjecctsInOU = Get-ADObject -filer * -SearchBase "OU=Tier0,OU=admin,DC=domain,DC=com"

$domaincontrollers = Get-ADDomainController -Filter *

#Adding all adobjects into single variable to enable looping through data.
$totalobjects = ($Privilegedgroups + $PrivilegedGroupMembers + $domaincontrollers + $PrivilegedServerObjects + $ObjecctsInOU) | select -Unique

$rougeownerobjects = $totalobjects | foreach-object{

    $owner = (Get-Acl -Path ("AD:\" + $_.distinguishedname) -ErrorAction Stop).Owner
    if($owner -notmatch "Domain Admins|SYSTEM"){
            #Create new psobject with owner and attributes available for output
            $Object = New-Object PSObject -Property @{
                distinguishedname    = $_.distinguishedname
                owner                = $owner
                ObjectClass          = $_.ObjectClass
            }
        
            $Object        
    }
}

$rougeownerobjects | out-gridview #The Out-GridView cmdlet sends the output from a command to a grid view window where the output is displayed in an interactive table.
```

After reviewing the output, a script could be used to fix deviating objects.

## Set owner rights on AD objects

To set owners on existing objects, I have written this small function.

{% include codeHeader.html %}

```powershell
<#
.SYNOPSIS
Sets the owner of an Active Directory object to a specified group.

.DESCRIPTION
This function sets the owner of an Active Directory object to a specified group.
The object must be of type user, computer, organizationalUnit, or group.

.PARAMETER NewOwnerGroup
The name of the group that should be set as the new owner of the object.

.PARAMETER ADObject
The Active Directory object to set the owner for.

.EXAMPLE
SetObjectOwner -NewOwnerGroup "Domain Admins" -ADObject (Get-ADUser jdoe)

Sets the owner of the user account with the username "jdoe" to the "Domain Admins" group.

.NOTES
Author: [Author Name]
Date: [Date]
#>
Function Set-ADObjectOwner{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$NewOwnerGroup,
        [Parameter(Mandatory=$true,Position=1)]
        [Microsoft.ActiveDirectory.Management.ADObject]$ADObject
    )

    # Get the object's current ACL
    $objPath = "AD:\" + $ADObject.DistinguishedName
    $acl = Get-Acl -Path $objPath

    # Create a new NTAccount object for the new owner group
    $adAccount = New-Object System.Security.Principal.NTAccount((Get-ADDomain -Current LoggedOnUser).DNSRoot, $NewOwnerGroup)

    # Set the owner of the ACL to the new NTAccount object
    $acl.SetOwner([Security.Principal.NTaccount]$adAccount)

    # Apply the updated ACL to the object
    Set-Acl -Path $objPath -AclObject $acl
}
```

Leveraging the power of Powershell (pun intented) we can easily fix multiple objects using a relatively small effort. Here we are combining the script to detect with the function to fix.

The script can be downloaded [here](https://github.com/FrederikLeed/AD/blob/main/Delegation/fix_rouge_owners.ps1)

{% include codeHeader.html %}

```powershell
<#
.SYNOPSIS
Sets the owner of an Active Directory object to a specified group.

.DESCRIPTION
This function sets the owner of an Active Directory object to a specified group.
The object must be of type user, computer, organizationalUnit, or group.

.PARAMETER NewOwnerGroup
The name of the group that should be set as the new owner of the object.

.PARAMETER ADObject
The Active Directory object to set the owner for.

.EXAMPLE
SetObjectOwner -NewOwnerGroup "Domain Admins" -ADObject (Get-ADUser jdoe)

Sets the owner of the user account with the username "jdoe" to the "Domain Admins" group.

.NOTES
Author: [Author Name]
Date: [Date]
#>
Function Set-ADObjectOwner{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$NewOwnerGroup,
        [Parameter(Mandatory=$true,Position=1)]
        [Microsoft.ActiveDirectory.Management.ADObject]$ADObject
    )

    # Get the object's current ACL
    $objPath = "AD:\" + $ADObject.DistinguishedName
    $acl = Get-Acl -Path $objPath

    # Create a new NTAccount object for the new owner group
    $adAccount = New-Object System.Security.Principal.NTAccount((Get-ADDomain -Current LoggedOnUser).DNSRoot, $NewOwnerGroup)

    # Set the owner of the ACL to the new NTAccount object
    $acl.SetOwner([Security.Principal.NTaccount]$adAccount)

    # Apply the updated ACL to the object
    Set-Acl -Path $objPath -AclObject $acl
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
 
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Information','Warning','Error')]
        [string]$Severity = 'Information',

        [Parameter()]
        [string]$LogFile = '.\logs\$Scriptfilename.csv',

        [Parameter()]
        [string]$LogFormat = '{0:g} [{1}] {2}'
    )
 
    $logMessage = $LogFormat -f (Get-Date), $Severity, $Message

    [pscustomobject]@{
        Time = (Get-Date -f g)
        Message = $Message
        Severity = $Severity
    } | Export-Csv -Path $LogFile -Append -NoTypeInformation

    Write-Output $logMessage
 }

$Scriptfilename = $MyInvocation.MyCommand.Name

$AdminGroups = @"
Account Operators
Administrators
Backup Operators
Cert Publishers
DNSAdmins
Domain Admins
Enterprise Admins
Enterprise Key Admins
Key Admins
Print Operators
Replicator
Schema Admins
Server Operators
"@

#Modify this to match your environment
$PrivilegedServers = @"
adfs01
adfs02
ca01
ca02
aadc01
aadc02
"@

$Privilegedgroups = $AdminGroups.Split([System.Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries) | % {
    Get-ADGroup $_
}

$PrivilegedGroupMembers = $AdminGroups.Split([System.Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries) | % {
    Get-ADGroupMember $_ -Recursive
}

$PrivilegedServerObjects = $privilegedservers.Split([System.Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries) | % {
    Get-ADComputer $_
}

#If AD tiering is applied, looping through all objects within tier0 would be advised.
$ObjecctsInOU = Get-ADObject -filer * -SearchBase "OU=Tier0,OU=admin,DC=domain,DC=com"

$domaincontrollers = Get-ADDomainController -Filter *

#Adding all adobjects into single variable to enable looping through data.
$totalobjects = ($Privilegedgroups + $PrivilegedGroupMembers + $domaincontrollers + $PrivilegedServerObjects + $ObjecctsInOU) | select -Unique

$totalobjects | foreach-object{

    $owner = (Get-Acl -Path ("AD:\" + $_.distinguishedname) -ErrorAction Stop).Owner
    if($owner -notmatch "Domain Admins|SYSTEM"){
        Try{
            Set-ADObjectOwner -NewOwnerGroup "Domain Admins" -ADObject $_
            Write-Log -Message ($_.name + " OldOwner: " + $owner) -Severity Information
        }catch{
            Write-Log -Message ("Operations failed: " + $_.name + " Error: " + $Error) -Severity Error
        }
    }
}
```

### Scheduling script to prevent future deviances

**Important!**
While scheduling something like this makes sense, you need to make sure that the host used to execute a task like this, is protected at a level equal to domain controllers. The account used to execute the script needs domain admin. While it IS possible to delegate permissions where membership of the domain admins group is not required, BUT, the delegated permission would enable escalation to domain admin anyway.  (Modify owner and change DACL)

Scheduled scripts need to run with a set of stored credentials. To reduce risk, we use [gMSA](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)

 gMSAs can help improve security by reducing the risk of credential theft and reducing the need for manual password management. With gMSAs, passwords are managed automatically by Active Directory, and are automatically changed every 30 days, making it more difficult for an attacker to gain access to the account.

Small function to use powershell to create a new gMSA

{% include codeHeader.html %}

```powershell
Function NewgMSA{
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$gMSAname,

    [Parameter(Mandatory = $true)]
    [string]$schedulingHost
)

$ADDomain = Get-ADDomain

# Create gMSA
    New-ADServiceAccount -Name $gMSAname -DNSHostName ($gMSAname + "." + $ADDomain.DNSRoot) -Enabled $True

# Grant permission to retrieve managed password to scheduling host
    $props = @{
        Identity = $gMSAname
        PrincipalsAllowedToRetrieveManagedPassword = $schedulingHost
    }
    Set-ADServiceAccount @props
}
```

### Scheduled task creation

Create scheduled task using ui.

- Program: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- Argument: -file "FixRougeOwners.ps1"
- Start in: c:\scripts

![Task settings](/assets/images/schtask_ownerrights.png)

Then, after the task has been created, make it run using the gMSA.

Example:

{% include codeHeader.html %}

```batch
schtasks.exe /change /RU "DOMAIN\gMSA_OwnerRights$" /TN "\Maintenance\FixOwnerPermission" /RP
```
