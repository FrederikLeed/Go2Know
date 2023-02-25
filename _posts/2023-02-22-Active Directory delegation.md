---
title: "Delegating permissions in Active Directory"
categories:
  - Active Directory
author:
 - Frederik Leed
tags:
  - Microsoft
  - Security
  - Powershell
  - DoTheBasics
layout: post
---

Least privilege wins! Delegate permission in every case, never use built-in operator groups.

![Delegated administration](/assets/images/groups.png){:width="180px"}

## Delegated administration

Active Directory delegation is the process of assigning specific administrative tasks to designated users or groups within an organization. This allows for a more efficient and effective management of the Active Directory environment by distributing tasks and responsibilities to those who need them.

There are several different levels of delegation in Active Directory, each with different permissions and capabilities. Common delegation examples:

- Control access to specific objects: This level of delegation allows administrators to grant or deny access to specific objects in Active Directory, such as users, groups, and computers.

- Create, delete, and modify objects: This level of delegation allows administrators to create, delete, and modify objects in Active Directory, such as users, groups, and computers.

- Create, delete, and manage organizational units: This level of delegation allows administrators to create, delete, and manage organizational units in Active Directory, which can be used to group and organize objects.

By delegating administrative tasks in Active Directory, organizations can ensure that only the necessary personnel have access to critical functions, while reducing the risk of unauthorized access and security breaches. It can also help to streamline administrative workflows and improve overall efficiency in managing the Active Directory environment.

![Company structure](/assets/images/AD_Company_structure.png){:width="360px"}

## Report on existing delegations ![powershell](/assets/images/powershell.png){:width="30px"}

The following script is designed to analyze the permissions that are set on a particular OU in Active Directory. By focusing on this specific level, the script provides a detailed overview of the permissions that have been granted within that OU. This information can be used to identify unnecessary permissions and clean them up, or to better understand the current delegation of permissions and make improvements as necessary.

{% include codeHeader.html %}

```powershell
<#
.SYNOPSIS
    This script uses the ADSecurityReporter module to scan a specific OU in the Active Directory, exclude certain permission types, and filter the results to exclude certain groups or accounts. The results are then displayed in a grid view.
.DESCRIPTION
    This script uses the Get-PscActiveDirectoryACL cmdlet from the ADSecurityReporter module to scan a specific OU in the Active Directory and retrieve the access control lists (ACLs) for each object in the specified OU. The script then applies several filters to exclude certain permission types, such as inherited permissions, and certain groups or accounts, such as Domain Admins and Exchange. Finally, the script displays the filtered results in a grid view for easy analysis.
.EXAMPLE
    PS C:\> .\Get-ActiveDirectoryACL.ps1
    This example scans the default OU for the Active Directory and displays the results in a grid view.
.NOTES
    Author: [Author Name]
    Date: [Date]
#>

# Import the ADSecurityReporter module
Import-Module ADSecurityReporter

# Scan a specific OU in the Active Directory and exclude certain permission types
Get-PscActiveDirectoryACL -ScanDNName "OU=Company,DC=Domain,DC=com" `
-ExcludeInheritedPermission `
-ExcludeNTAUTHORITY `
-ExcludeBuiltIN `
-DontRunBasicSecurityCheck `
-ExcludeCreatorOwner `
-ExcludeEveryOne |

# Filter the results to exclude certain groups or accounts
Where-Object {
    $_.'Assigned To' -notmatch "s-1-5-32-548|s-1-5-32-554|Domain Admins|exchange|organization"
    # Uncomment the following line to include only a specific group or account
    # $_.'Assigned To' -match "sec-ad-nr"
} |

# Display the results in a grid view
Out-GridView
```

## Create new delegations ![powershell](/assets/images/powershell.png){:width="30px"}

This PowerShell script defines five functions that can be used to grant full delegation rights to a specified group over various Active Directory objects in a specified organizational unit (OU).

- The first function, SetFullUserDelegation, grants full delegation rights over users in the specified OU. It takes two parameters: $ou, which is the distinguished name of the OU in which permissions will be granted, and $group, which is the name of the group to which full delegation rights will be granted. Other functions take the same parameters.
- The second function, SetFullGroupDelegation, grants full delegation rights over groups in the specified OU.
- The third function, SetFullComputerDelegation, grants full delegation rights over computers in the specified OU.
- The fourth function, SetFullOUDelegation, grants full delegation for a given OU for a given group.
- The fifth function, SetPwdResetDelegation, grants delegation for password reset on a specified OU for a specified group.

These are common delegation functions. Variations can be created where a more detailed permissionset is granted. Like the SetPwdResetDelegation function. It does not grant full acces to users objects, but only enables password reset.

{% include codeHeader.html %}

```powershell
#This function sets the permissions for a specified group to have full delegation rights over users in the specified organizational unit (OU) in Active Directory.
Function SetFullUserDelegation{
    Param(
        $ou,   # distinguished name of the OU in which permissions will be granted
        $group # name of the group to which full delegation rights will be granted
    )

    # Get the current ACL for the OU
    $acl = get-acl ("ad:"+ $ou)

    # Get the SID of the specified group
    $group = Get-ADgroup $group
    $sid = new-object System.Security.Principal.SecurityIdentifier $group.SID
    
    # Set the object and inherited object GUIDs for the ACE that grants GenericAll rights
    $objecttypeguid = $AllGuid
    $inheritedobjecttypeguid = $UserGuid

    # Create an ACE that grants the specified group GenericAll rights on the users in the OU
    $identity = [System.Security.Principal.IdentityReference] $SID
    $adRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
    $type = [System.Security.AccessControl.AccessControlType] "Allow"
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"

    # Add the first access rule to the ACL
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$objecttypeguid,$inheritanceType,$inheritedobjecttypeguid))


    # Set the object and inherited object GUIDs for the ACE that grants CreateChild and DeleteChild rights
    $objecttypeguid = $UserGuid
    $inheritedobjecttypeguid = $AllGuid

    # Create an ACE that grants the specified group CreateChild and DeleteChild rights on users in the OU and its descendants
    $identity = [System.Security.Principal.IdentityReference] $SID
    $adRights = [System.DirectoryServices.ActiveDirectoryRights] "CreateChild, DeleteChild"
    $type = [System.Security.AccessControl.AccessControlType] "Allow"
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"

    # Add the second access rule to the ACL
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$objecttypeguid,$inheritanceType,$inheritedobjecttypeguid))

    # Set the new ACL for the OU
    Set-ACl -Path "AD:\$ou" -AclObject $acl
}
#This function sets the permissions for a specified group to have full delegation rights over groups in the specified organizational unit (OU) in Active Directory.
Function SetFullGroupDelegation{
    Param(
        $ou,   # distinguished name of the OU in which permissions will be granted
        $group # name of the group to which full delegation rights will be granted
    )

    # Get the current ACL for the OU       
    $acl = get-acl ("ad:"+ $ou)

    # Get the SID of the specified group
    $group = Get-ADgroup $group
    $sid = new-object System.Security.Principal.SecurityIdentifier $group.SID

    # Set the object and inherited object GUIDs for the ACE that grants GenericAll rights        
    $objecttypeguid = $AllGuid
    $inheritedobjecttypeguid = $GroupGuid

    # Create an ACE that grants the specified group GenericAll rights on the groups in the OU
    $identity = [System.Security.Principal.IdentityReference] $SID
    $adRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
    $type = [System.Security.AccessControl.AccessControlType] "Allow"
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"

    # Add the first access rule to the ACL
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$objecttypeguid,$inheritanceType,$inheritedobjecttypeguid))

    # Set the object and inherited object GUIDs for the ACE that grants CreateChild and DeleteChild rights
    $objecttypeguid = $GroupGuid
    $inheritedobjecttypeguid = $AllGuid

    # Create an ACE that grants the specified group CreateChild and DeleteChild rights on groups in the OU and its descendants
    $identity = [System.Security.Principal.IdentityReference] $SID
    $adRights = [System.DirectoryServices.ActiveDirectoryRights] "CreateChild, DeleteChild"
    $type = [System.Security.AccessControl.AccessControlType] "Allow"
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"

    # Add the second access rule to the ACL
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$objecttypeguid,$inheritanceType,$inheritedobjecttypeguid))

    # Set the new ACL for the OU
    Set-ACl -Path "AD:\$ou" -AclObject $acl
}
#This function sets the permissions for a specified group to have full delegation rights over the specified organizational unit (OU) in Active Directory.
Function SetFullComputerDelegation{
    Param(
        $ou,    # distinguished name of the OU in which permissions will be granted
        $group  # name of the group to which full delegation rights will be granted
    )

    # Get the current ACL for the OU
    $acl = get-acl ("ad:"+ $ou)

    # Get the SID of the specified group
    $group = Get-ADgroup $group
    $sid = new-object System.Security.Principal.SecurityIdentifier $group.SID

    # Set the object and inherited object GUIDs for the ACE that grants GenericAll rights
    $objecttypeguid = $AllGuid
    $inheritedobjecttypeguid = $ComputerGuid

    # Create an ACE that grants the specified group GenericAll rights on the OU and its descendants
    $identity = [System.Security.Principal.IdentityReference] $SID
    $adRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
    $type = [System.Security.AccessControl.AccessControlType] "Allow"
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"

    # Add the first access rule to the ACL
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$objecttypeguid,$inheritanceType,$inheritedobjecttypeguid))

    # Set the object and inherited object GUIDs for the ACE that grants CreateChild and DeleteChild rights
    $objecttypeguid = $ComputerGuid
    $inheritedobjecttypeguid = $AllGuid

    # Create an ACE that grants the specified group CreateChild and DeleteChild rights on the OU and its descendants
    $identity = [System.Security.Principal.IdentityReference] $SID
    $adRights = [System.DirectoryServices.ActiveDirectoryRights] "CreateChild, DeleteChild"
    $type = [System.Security.AccessControl.AccessControlType] "Allow"
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
    
    # Add the second access rule to the ACL
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$objecttypeguid,$inheritanceType,$inheritedobjecttypeguid))

    # Set the new ACL for the OU
    Set-ACl -Path "AD:\$ou" -AclObject $acl
}
# Function to set full delegation for a given OU for a given group
Function SetFullOUDelegation{
    Param(
        $ou,    # Organizational Unit to set delegation on
        $group  # Group to set delegation for
    )

    # Get the current ACL for the specified OU
    $acl = get-acl ("ad:"+ $ou)

    # Get the group object
    $group = Get-ADgroup $group

    # Get the SID for the group
    $sid = new-object System.Security.Principal.SecurityIdentifier $group.SID

    # Set the object type and inheritance type for the first access rule
    $objecttypeguid = $AllGuid
    $inheritedobjecttypeguid = $OrganizationalUnitGuid

    # Set the identity, access rights, access control type, and inheritance type for the first access rule
    $identity = [System.Security.Principal.IdentityReference] $SID
    $adRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
    $type = [System.Security.AccessControl.AccessControlType] "Allow"
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"

    # Add the first access rule to the ACL
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$objecttypeguid,$inheritanceType,$inheritedobjecttypeguid))

    # Set the object type and inheritance type for the second access rule
    $objecttypeguid = $OrganizationalUnitGuid
    $inheritedobjecttypeguid = $OrganizationalUnitGuid

    # Set the identity, access rights, access control type, and inheritance type for the second access rule
    $identity = [System.Security.Principal.IdentityReference] $SID
    $adRights = [System.DirectoryServices.ActiveDirectoryRights] "CreateChild, DeleteChild"
    $type = [System.Security.AccessControl.AccessControlType] "Allow"
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"

    # Add the second access rule to the ACL
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$objecttypeguid,$inheritanceType,$inheritedobjecttypeguid))

    # Set the new ACL for the specified OU
    Set-ACl -Path "AD:\$ou" -AclObject $acl
}
# This function sets delegation for password reset on a specified OU for a specified group
Function SetPwdResetDelegation{
    Param(
        $OU,    # The distinguished name of the OU
        $GroupName   # The name of the group for which delegation is to be set
    )

    # Get the current access control list (ACL) for the OU
    $acl = get-acl ("ad:"+ $OU)

    # Get the security identifier (SID) of the group
    $group = Get-ADgroup $GroupName
    $sid = new-object System.Security.Principal.SecurityIdentifier $group.SID

    # Define the values for the first access rule (pwdLastSet)
    $inheritedobjecttypeguid = $UserGuid
    $identity = [System.Security.Principal.IdentityReference] $SID
    $adRights = [System.DirectoryServices.ActiveDirectoryRights] "ReadProperty, WriteProperty"
    $type = [System.Security.AccessControl.AccessControlType] "Allow"
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
    $objecttypeguid = $pwdLastSetGuid

    # Create the first access rule and add it to the ACL
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$objecttypeguid,$inheritanceType,$inheritedobjecttypeguid))

    # Define the values for the second access rule (LockoutTime)
    $identity = [System.Security.Principal.IdentityReference] $SID
    $adRights = [System.DirectoryServices.ActiveDirectoryRights] "ReadProperty, WriteProperty"
    $type = [System.Security.AccessControl.AccessControlType] "Allow"
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
    $objecttypeguid = $LockoutTimeGuid

    # Create the second access rule and add it to the ACL
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$objecttypeguid,$inheritanceType,$inheritedobjecttypeguid))

    # Define the values for the third access rule (PasswordReset)
    $identity = [System.Security.Principal.IdentityReference] $SID
    $adRights = [System.DirectoryServices.ActiveDirectoryRights] "ExtendedRight"
    $type = [System.Security.AccessControl.AccessControlType] "Allow"
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
    $objecttypeguid = $PasswordResetGuid

    # Create the third access rule and add it to the ACL
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$objecttypeguid,$inheritanceType,$inheritedobjecttypeguid))

    # Set the updated ACL on the OU
    Set-ACL -Path "AD:\$ou" -AclObject $acl
}

#Dependencies
Import-Module ActiveDirectory
Import-Module admpwd.ps

#Guid references
    #ObjectGUIDs
    $UserGuid                     = [GUID]::Parse('bf967aba-0de6-11d0-a285-00aa003049e2') #http://www.selfadsi.org/deep-inside/ad-security-descriptors.htm
    $GroupGuid                    = [GUID]::Parse('bf967a9c-0de6-11d0-a285-00aa003049e2') #http://www.selfadsi.org/deep-inside/ad-security-descriptors.htm
    $ComputerGuid                 = [GUID]::Parse('bf967a86-0de6-11d0-a285-00aa003049e2') #http://www.selfadsi.org/deep-inside/ad-security-descriptors.htm
    $OrganizationalUnitGuid       = [GUID]::Parse('bf967aa5-0de6-11d0-a285-00aa003049e2') #http://www.selfadsi.org/deep-inside/ad-security-descriptors.htm
    $ContactGuid                  = [GUID]::Parse('5cb41ed0-0e4c-11d0-a286-00aa003049e2') #http://www.selfadsi.org/deep-inside/ad-security-descriptors.htm
    
    #All
    $AllGuid                      = [GUID]::Parse('00000000-0000-0000-0000-000000000000')
    
    #User
    $PasswordResetGuid            = [GUID]::Parse('00299570-246d-11d0-a768-00aa006e0529') #https://learn.microsoft.com/en-us/windows/win32/adschema/a-othermobile
    $pwdLastSetGuid               = [GUID]::Parse('bf967a0a-0de6-11d0-a285-00aa003049e2') #https://learn.microsoft.com/en-us/windows/win32/adschema/a-pwdlastset
    $LockoutTimeGuid              = [GUID]::Parse('28630ebf-41d5-11d1-a9c1-0000f80367c1') #https://learn.microsoft.com/en-us/windows/win32/adschema/a-lockouttime
    
    #Set permission Company
    $ou = "OU=Department,OU=Company,DC=domain,DC=com"
    
    #Set group delegation
        SetFullGroupDelegation -ou $ou -group "SEC-AD-Department-GroupAdmin"
    #Set user delegation
        SetFullUserDelegation -ou $ou -group "SEC-AD-Department-UserAdmin"
    #Set computer delegation
        SetFullComputerDelegation -ou $ou -group "SEC-AD-Department-ComputerAdmin"
    #Set OU delegation
        SetFullOUDelegation -ou $ou -group "SEC-AD-Department-OUAdmin"
    #Set PwdReset delegation
        SetPwdResetDelegation -ou $ou -group "SEC-AD-Department-PwdReset"
```
