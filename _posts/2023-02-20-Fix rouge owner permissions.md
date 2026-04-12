---
title: "Fixing Rogue Object Ownership in Active Directory"
excerpt: "Object ownership in AD grants implicit WriteDacl — a direct path to privilege escalation. Here's how to detect and fix it."
date: 2023-02-20
last_modified_at: 2023-02-20
categories:
  - Security
tags:
  - Active Directory
  - PowerShell
  - Least Privilege
toc: true
toc_label: "Contents"
toc_sticky: true
header:
  teaser: /assets/images/Microsoft_ActiveDirectory.png
---

I keep running into this during security assessments: a helpdesk admin created a service account three years ago, and nobody noticed that they became the owner of that object. That service account is now a member of Domain Admins — and the helpdesk admin can take full control of it without anyone granting them a single permission.

Object ownership in AD is that dangerous. The owner has implicit `WRITE_DAC`, which means they can modify the object's permissions. From there it's three steps to Domain Admin.

## The attack chain

The exploitation is straightforward:

1. **Owner modifies the DACL** — grants themselves full control on the object
2. **Resets the password** — or writes any attribute they want
3. **Authenticates as that account** — game over

This works on any object type. Own a domain controller computer object? Grant yourself replication rights, dump every hash in the domain. Own the domain head itself? You control the entire directory.

This is not theoretical. We see it in production environments constantly.

## What to check

The default owner is whoever created the object. That's fine for regular user accounts, but for anything Tier 0 it's a problem. Focus on the objects where compromise means domain or forest compromise:

| Object type | Examples |
|---|---|
| Built-in admin groups | Domain Admins, Enterprise Admins, Schema Admins, Administrators |
| Operator groups | Account Operators, Backup Operators, Server Operators, Print Operators |
| Domain controllers | All DC computer objects |
| Tier 0 servers | Entra Connect, ADFS, ADCS, SCCM |
| Privileged users | Members of the groups above |
| Domain object | The domain head itself |

The expected owner for all of these is `Domain Admins` or `NT AUTHORITY\SYSTEM`. Anything else should be investigated.

## Detect and fix

Check the owner of every privileged object. If it's not `Domain Admins` or `SYSTEM` — fix it.

```powershell
# Collect privileged objects — groups, members, DCs
$objects = @()
$objects += 'Account Operators','Administrators','Backup Operators','Domain Admins',
            'Enterprise Admins','Schema Admins','Server Operators' | ForEach-Object {
    Get-ADGroup $_
    Get-ADGroupMember $_ -Recursive
}
$objects += Get-ADDomainController -Filter * | ForEach-Object { Get-ADComputer $_.Name }
$objects = $objects | Sort-Object DistinguishedName -Unique

# Check and fix ownership
$domain = (Get-ADDomain).DNSRoot
$newOwner = New-Object System.Security.Principal.NTAccount($domain, 'Domain Admins')

foreach ($obj in $objects) {
    $acl = Get-Acl -Path "AD:\$($obj.DistinguishedName)"
    if ($acl.Owner -notmatch 'Domain Admins|SYSTEM') {
        Write-Output "Fixing: $($obj.Name) (owner: $($acl.Owner))"
        $acl.SetOwner($newOwner)
        Set-Acl -Path "AD:\$($obj.DistinguishedName)" -AclObject $acl
    }
}
```

Add your Tier 0 servers (Entra Connect, ADFS, ADCS, etc.) to the `$objects` collection to cover those too.

## Automate it

Ownership drifts — every time someone creates an object, they become the owner. Schedule this to run regularly using a **gMSA** so there are no stored credentials.

**Important:** The account running this needs Domain Admin level access. The host executing it must be protected at the same tier as your domain controllers.

## Conclusion

Rogue object ownership is one of those things that's easy to overlook and trivial to exploit. Three steps from a forgotten owner permission to Domain Admin. Detect it, fix it, schedule it — and stop worrying about it.
