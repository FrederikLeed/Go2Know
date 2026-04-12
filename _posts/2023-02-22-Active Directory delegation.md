---
title: "Delegating Permissions in Active Directory"
excerpt: "Stop using built-in operator groups. Delegate permissions properly with least privilege."
date: 2023-02-22
last_modified_at: 2023-02-22
categories:
  - Active Directory
tags:
  - PowerShell
  - Security
  - Least Privilege
toc: true
toc_label: "Contents"
toc_sticky: true
---

Least privilege wins. Every time I look at an AD environment, I find helpdesk accounts in Domain Admins "because they need to reset passwords." Operator groups with members nobody can explain. Permissions granted directly to user accounts instead of groups.

Stop using built-in operator groups. Delegate the exact permissions needed, to a group, on the specific OU where they're needed — nothing more.

## Why delegation matters

Built-in groups like Account Operators and Server Operators grant far more access than most admins realize. Account Operators can create and modify users and groups anywhere in the domain. Server Operators can log on to domain controllers. These are effectively Tier 0 privileges handed out like candy.

Proper delegation means:

- Permissions scoped to a specific OU — not the entire domain
- Granted to a security group — never to a user account directly
- Limited to the exact object type (users, groups, computers, OUs)
- Reviewable — you can report on who has what

## Report on existing delegations

Before changing anything, audit what's already delegated. The [ADSecurityReporter](https://www.powershellgallery.com/packages/ADSecurityReporter) module makes this straightforward.

```powershell
Import-Module ADSecurityReporter

Get-PscActiveDirectoryACL -ScanDNName "OU=Company,DC=Domain,DC=com" `
    -ExcludeInheritedPermission `
    -ExcludeNTAUTHORITY `
    -ExcludeBuiltIN `
    -ExcludeCreatorOwner `
    -ExcludeEveryOne |
Where-Object {
    $_.'Assigned To' -notmatch "s-1-5-32-548|s-1-5-32-554|Domain Admins|exchange|organization"
} | Out-GridView
```

This shows you every non-inherited, non-default ACE on the OU. Clean up anything that shouldn't be there.

## Create new delegations

Here are the building blocks for proper delegation. Each function grants a specific permission type on a specific object class within an OU.

The pattern is always the same: get the OU ACL, create an ACE with the right GUIDs, apply it.

```powershell
Import-Module ActiveDirectory

# Object class GUIDs
$UserGuid     = [GUID]'bf967aba-0de6-11d0-a285-00aa003049e2'
$GroupGuid    = [GUID]'bf967a9c-0de6-11d0-a285-00aa003049e2'
$ComputerGuid = [GUID]'bf967a86-0de6-11d0-a285-00aa003049e2'
$OUGuid       = [GUID]'bf967aa5-0de6-11d0-a285-00aa003049e2'
$AllGuid      = [GUID]'00000000-0000-0000-0000-000000000000'

# Extended rights GUIDs
$PasswordResetGuid = [GUID]'00299570-246d-11d0-a768-00aa006e0529'
$pwdLastSetGuid    = [GUID]'bf967a0a-0de6-11d0-a285-00aa003049e2'
$LockoutTimeGuid   = [GUID]'28630ebf-41d5-11d1-a9c1-0000f80367c1'

function Set-OUDelegation {
    param($OU, $Group, $ObjectGuid, $Rights)
    $acl = Get-Acl "AD:\$OU"
    $sid = (Get-ADGroup $Group).SID

    # Full control on objects of the specified class
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
        $sid, $Rights, 'Allow', $AllGuid, 'Descendents', $ObjectGuid))

    # Create/delete objects of the specified class
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
        $sid, 'CreateChild,DeleteChild', 'Allow', $ObjectGuid, 'All', $AllGuid))

    Set-Acl "AD:\$OU" $acl
}
```

### Usage

```powershell
$ou = "OU=Department,OU=Company,DC=domain,DC=com"

# Full user administration on the OU
Set-OUDelegation -OU $ou -Group "SEC-AD-Dept-UserAdmin" -ObjectGuid $UserGuid -Rights "GenericAll"

# Full group administration
Set-OUDelegation -OU $ou -Group "SEC-AD-Dept-GroupAdmin" -ObjectGuid $GroupGuid -Rights "GenericAll"

# Full computer administration
Set-OUDelegation -OU $ou -Group "SEC-AD-Dept-ComputerAdmin" -ObjectGuid $ComputerGuid -Rights "GenericAll"

# Full OU administration
Set-OUDelegation -OU $ou -Group "SEC-AD-Dept-OUAdmin" -ObjectGuid $OUGuid -Rights "GenericAll"
```

### Password reset only

Not every delegation needs full control. Here's a minimal password-reset-only delegation — reset password, unlock account, and set pwdLastSet:

```powershell
function Set-PwdResetDelegation {
    param($OU, $Group)
    $acl = Get-Acl "AD:\$OU"
    $sid = (Get-ADGroup $Group).SID

    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
        $sid, 'ExtendedRight', 'Allow', $PasswordResetGuid, 'Descendents', $UserGuid))
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
        $sid, 'ReadProperty,WriteProperty', 'Allow', $pwdLastSetGuid, 'Descendents', $UserGuid))
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
        $sid, 'ReadProperty,WriteProperty', 'Allow', $LockoutTimeGuid, 'Descendents', $UserGuid))

    Set-Acl "AD:\$OU" $acl
}

Set-PwdResetDelegation -OU $ou -Group "SEC-AD-Dept-PwdReset"
```

## Conclusion

Every permission you delegate is one less reason to hand out Domain Admin. Start with password reset — it's the most common request and the easiest to scope. Then move on to user, group, and computer admin. The goal is empty operator groups and no helpdesk accounts in Domain Admins.
