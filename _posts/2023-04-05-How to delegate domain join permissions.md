---
title: "Delegating Domain Join Permissions with Least Privilege"
excerpt: "Stop using Domain Admins to join machines. Delegate the exact permissions needed — nothing more."
date: 2023-04-05
last_modified_at: 2023-04-05
categories:
  - Security
tags:
  - Active Directory
  - PowerShell
  - Least Privilege
toc: true
toc_label: "Contents"
toc_sticky: true
---

The account used to join computers to the domain is one of the most over-privileged accounts in most AD environments. Way too often it's a member of Domain Admins or Administrators — and its credentials are exposed during OS deployment by design.

An attacker on the network during an OSD task sequence can grab those credentials. If the account is Domain Admin, that's game over. If it's a properly delegated service account, the blast radius is "they can join computers to one OU."

## Best practices

- **Single-use service accounts** — one per deployment scenario
- **Unique passwords** — never reuse across accounts
- **Separate accounts for servers and workstations** — different tiers, different blast radius
- **Delegate to a group** — add the service account to a security group, delegate permissions to the group
- **Set MachineAccountQuota to 0** — prevents regular users from joining machines to the domain

For the full rationale, read the [de-privileging article from Microsoft IR](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/why-de-privileging/ba-p/3779519).

## The delegation

A domain join account needs exactly five permissions on the target OU:

1. Create/delete computer objects
2. Reset password
3. Read/write account restrictions
4. Write DNS host name
5. Write service principal name

Nothing else.

```powershell
$rootdse = Get-ADRootDSE
$extendedrightsmap = @{}
Get-ADObject -SearchBase $rootdse.ConfigurationNamingContext `
    -LDAPFilter "(&(objectclass=controlAccessRight)(rightsguid=*))" `
    -Properties displayName, rightsGuid |
    ForEach-Object { $extendedrightsmap[$_.displayName] = [System.GUID]$_.rightsGuid }

$spnguid = [System.Guid](Get-ADObject "CN=Service-Principal-Name,$($rootdse.SchemaNamingContext)" -Properties schemaIDGUID).schemaIDGUID
$computerguid = [System.Guid](Get-ADObject "CN=Computer,$($rootdse.SchemaNamingContext)" -Properties schemaIDGUID).schemaIDGUID

function Set-DomainJoinPermissions($GroupName, $OU) {
    $sid = (Get-ADGroup $GroupName).SID
    $acl = Get-Acl "AD:\$OU"

    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $sid, "CreateChild,DeleteChild", "Allow", $computerguid))
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $sid, "ExtendedRight", "Allow", $extendedrightsmap["Reset Password"], "Descendents", $computerguid))
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $sid, "ReadProperty,WriteProperty", "Allow", $extendedrightsmap["Account Restrictions"], "Descendents", $computerguid))
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $sid, "WriteProperty", "Allow", $extendedrightsmap["DNS Host Name Attributes"], "Descendents", $computerguid))
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $sid, "WriteProperty", "Allow", $spnguid, "Descendents", $computerguid))

    Set-Acl "AD:\$OU" $acl
}

Set-DomainJoinPermissions -GroupName "SEC-DomainJoin-Workstations" -OU "OU=Workstations,DC=domain,DC=com"
```

For a more complete solution that also creates the service account, security group, and sets MachineAccountQuota — see [this script](https://github.com/FrederikLeed/scripts-n-queries/blob/55bcb1699f9cbe62e8c38f5442c417eb5e2cdea2/ActiveDirectory/Delegate_domain_join.ps1) on GitHub.

## Conclusion

Five ACE rules. That's all a domain join account needs. Everything beyond that is unnecessary risk. De-privilege your deployment accounts — it's one of the easiest wins in AD security.
