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
---

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

```Powershell
        <#
            .SYNOPSIS
            
            .DESCRIPTION

            .EXAMPLE
        #>
```

## Create new delegations ![powershell](/assets/images/powershell.png){:width="30px"}

```Powershell
        <#
            .SYNOPSIS
            Adds permission on supplied OrganizationalUnit to the supplied AD group
            
            .DESCRIPTION
            This function will delegate this permissionset: Full control on all user properties and ability to create and delete user objects.

            Rights          : Full Control ==> All Properties
            TargettedObject : User

            Rights          : CreateChild, DeleteChild ==> User
            TargettedObject : All AD Objects

            .EXAMPLE
            SetFullUserDelegation -ou "OU=UserAccounts,OU=Company,DC=domain,DC=com" -group "SEC-AD-CUA-UserAdmin" 
        #>
```
