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

BloodHound maps this as an `Owns` edge, and the exploitation is straightforward:

1. **Owner modifies the DACL** — grants themselves `GenericAll` on the object
2. **Resets the password** — or writes any attribute they want
3. **Authenticates as that account** — game over

This works on any object type. Own a domain controller computer object? Grant yourself `DCSync` rights, dump every hash in the domain. Own the domain head itself? You control the entire directory.

This maps to [MITRE T1222.001](https://attack.mitre.org/techniques/T1222/001/) and both BloodHound and AD_Miner flag these paths automatically. The chain is `WriteOwner → WriteDacl → GenericAll` — and it's not theoretical. We see it in production environments constantly.

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

The expected owner for all of these is `Domain Admins` or `NT AUTHORITY\SYSTEM`. Anything else is a finding worth investigating.

## Detect rogue ownership

This script collects all privileged objects and flags any where the owner is unexpected.

```powershell
# Privileged built-in groups to check
$AdminGroups = @(
    'Account Operators', 'Administrators', 'Backup Operators',
    'Cert Publishers', 'DNSAdmins', 'Domain Admins',
    'Enterprise Admins', 'Enterprise Key Admins', 'Key Admins',
    'Print Operators', 'Replicator', 'Schema Admins', 'Server Operators'
)

# Tier 0 servers — adjust to match your environment
$PrivilegedServers = @('adfs01', 'adfs02', 'ca01', 'ca02', 'aadc01', 'aadc02')

# Collect all privileged AD objects
$privilegedObjects = @()
$privilegedObjects += $AdminGroups | ForEach-Object { Get-ADGroup $_ }
$privilegedObjects += $AdminGroups | ForEach-Object { Get-ADGroupMember $_ -Recursive }
$privilegedObjects += Get-ADDomainController -Filter * | ForEach-Object { Get-ADComputer $_.Name }
$privilegedObjects += $PrivilegedServers | ForEach-Object { Get-ADComputer $_ }

# Deduplicate
$privilegedObjects = $privilegedObjects | Sort-Object DistinguishedName -Unique

# Check ownership
$rogueOwners = foreach ($obj in $privilegedObjects) {
    $owner = (Get-Acl -Path "AD:\$($obj.DistinguishedName)").Owner
    if ($owner -notmatch 'Domain Admins|SYSTEM') {
        [PSCustomObject]@{
            Name              = $obj.Name
            ObjectClass       = $obj.ObjectClass
            Owner             = $owner
            DistinguishedName = $obj.DistinguishedName
        }
    }
}

$rogueOwners | Format-Table -AutoSize
```

If the output is empty — you're clean. If not, keep reading.

## Fix ownership

Small function that sets the owner of any AD object to a specified group:

```powershell
function Set-ADObjectOwner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$NewOwnerGroup,

        [Parameter(Mandatory, ValueFromPipeline)]
        [Microsoft.ActiveDirectory.Management.ADObject]$ADObject
    )
    process {
        $path = "AD:\$($ADObject.DistinguishedName)"
        $acl = Get-Acl -Path $path
        $domain = (Get-ADDomain -Current LoggedOnUser).DNSRoot
        $account = New-Object System.Security.Principal.NTAccount($domain, $NewOwnerGroup)
        $acl.SetOwner($account)
        Set-Acl -Path $path -AclObject $acl
    }
}
```

Pipe the detection output straight into the fix:

```powershell
# Fix all rogue owners — sets ownership to Domain Admins
$rogueOwners | ForEach-Object {
    $obj = Get-ADObject $_.DistinguishedName
    try {
        $obj | Set-ADObjectOwner -NewOwnerGroup 'Domain Admins'
        Write-Output "Fixed: $($_.Name) (was: $($_.Owner))"
    }
    catch {
        Write-Warning "Failed: $($_.Name) — $($_.Exception.Message)"
    }
}
```

## Automate it

Ownership drifts. Every time someone creates an object, they become the owner. A privileged group created by a junior admin today is a finding waiting to happen. Schedule the fix to run regularly.

**Important:** The account running this needs the ability to take ownership and modify DACLs on privileged objects — effectively Domain Admin level access. The host executing it must be protected at the same tier as your domain controllers.

Use a **gMSA** instead of storing credentials. The password is managed by AD automatically — 240 bytes random, rotated every 30 days. Nothing to store, nothing to rotate.

```powershell
# Create gMSA for the scheduled task
$domain = Get-ADDomain
New-ADServiceAccount -Name 'gMSA_FixOwners' `
    -DNSHostName "gMSA_FixOwners.$($domain.DNSRoot)" -Enabled $true

# Allow the scheduling host to retrieve the managed password
Set-ADServiceAccount -Identity 'gMSA_FixOwners' `
    -PrincipalsAllowedToRetrieveManagedPassword 'YOURSERVER$'
```

Create the scheduled task, then switch it to the gMSA:

```batch
schtasks.exe /change /RU "DOMAIN\gMSA_FixOwners$" /TN "\Maintenance\FixOwnerPermission" /RP
```

## Conclusion

Rogue object ownership is one of those things that's easy to overlook and trivial to exploit. Three steps from a forgotten `Owns` edge to Domain Admin. Detect it, fix it, schedule it — and stop worrying about it.
