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

The default owner is whoever created the object. That's fine for regular user accounts, but for anything Tier 0 it's a problem.

Most blogs only talk about Domain Admins. In reality, AD has a lot of built-in groups that grant Tier 0 level access. These are the ones you need to check — all of them:

| RID | Group | Why it's Tier 0 |
|-----|-------|-----------------|
| 500 | Administrator | Built-in admin, exempt from auth policies |
| 502 | KRBTGT | Kerberos ticket-granting account — compromise = Golden Ticket |
| 512 | Domain Admins | Full domain control |
| 516 | Domain Controllers | Membership = DC-level trust |
| 518 | Schema Admins | Can modify the AD schema forest-wide |
| 519 | Enterprise Admins | Full forest control |
| 520 | Group Policy Creator Owners | Can create and modify GPOs |
| 526 | Key Admins | Can perform admin actions on key objects |
| 527 | Enterprise Key Admins | Forest-wide key administration |
| 544 | Administrators | Built-in local Administrators on DCs |
| 548 | Account Operators | Can create/modify users and groups |
| 549 | Server Operators | Can log on to and manage DCs |
| 550 | Print Operators | Can log on to DCs, load drivers |
| 551 | Backup Operators | Can read any file on DCs, including NTDS.dit |
| 555 | Remote Desktop Users (on DCs) | Interactive logon to domain controllers |
| 557 | Incoming Forest Trust Builders | Can create incoming forest trusts |
| 562 | Distributed COM Users (on DCs) | DCOM access to domain controllers |
| 569 | Cryptographic Operators | Can manage certificates and crypto |
| 580 | Remote Management Users (on DCs) | WinRM access to domain controllers |

On top of these groups and their members, check the domain object itself, all DC computer objects, and your Tier 0 infrastructure servers (Entra Connect, ADFS, ADCS, SCCM).

The expected owner for all of these is `Domain Admins` or `NT AUTHORITY\SYSTEM`. Anything else should be investigated.

## Detect and fix

Check the owner of every privileged object. If it's not `Domain Admins` or `SYSTEM` — fix it.

```powershell
# All built-in Tier 0 RIDs
$t0Rids = @(500,502,512,516,518,519,520,526,527,544,548,549,550,551,555,557,562,569,580)

# Resolve RIDs to AD objects in the current domain
$domainSID = (Get-ADDomain).DomainSID.Value
$objects = $t0Rids | ForEach-Object {
    Get-ADObject -Filter "objectSid -eq '$domainSID-$_'" -ErrorAction SilentlyContinue
}

# Add members of privileged groups, DCs, and Tier 0 servers
$objects += $objects | Where-Object objectClass -eq 'group' | ForEach-Object {
    Get-ADGroupMember $_ -Recursive -ErrorAction SilentlyContinue
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

Add your Tier 0 infrastructure servers (Entra Connect, ADFS, ADCS, etc.) to `$objects` to cover those too.

## Automate it

Ownership drifts — every time someone creates an object, they become the owner. Schedule this to run regularly using a **gMSA** so there are no stored credentials.

**Important:** The account running this needs Domain Admin level access. The host executing it must be protected at the same tier as your domain controllers.

## Conclusion

Rogue object ownership is one of those things that's easy to overlook and trivial to exploit. Three steps from a forgotten owner permission to Domain Admin. Detect it, fix it, schedule it — and stop worrying about it.
