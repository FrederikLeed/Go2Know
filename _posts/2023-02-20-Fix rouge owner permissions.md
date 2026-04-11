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

Every object in Active Directory has an owner. That owner has implicit `WRITE_DAC` — the ability to modify the object's permissions. If a non-admin user owns a privileged object, they can grant themselves full control without any additional rights.

This is [MITRE T1222.001](https://attack.mitre.org/techniques/T1222/001/) — and tools like BloodHound map it as an `Owns` edge directly to the target.

## Why ownership matters

The owner field lives in the security descriptor. It implicitly grants two rights:

- **READ_CONTROL** — read the DACL
- **WRITE_DAC** — modify the DACL

`WRITE_DAC` is the dangerous one. An attacker who owns a Domain Admin account can:

1. Grant themselves `GenericAll` on the object
2. Reset the password
3. Authenticate as that account

The same applies to computer objects. Own a domain controller? Write its DACL, grant yourself `DCSync` rights, dump every credential in the domain.

This is not theoretical — it's a three-step chain: `WriteOwner → WriteDacl → GenericAll`. BloodHound and AD_Miner flag these paths automatically.

## What should be checked

Focus on objects where compromise means domain or forest compromise:

| Object type | Examples |
|---|---|
| Built-in admin groups | Domain Admins, Enterprise Admins, Schema Admins, Administrators |
| Operator groups | Account Operators, Backup Operators, Server Operators, Print Operators |
| Domain controllers | All DC computer objects |
| Tier 0 servers | Entra Connect, ADFS, ADCS, SCCM |
| Privileged users | Members of the groups above |
| Domain object | The domain head itself |

The expected owner for all of these is `Domain Admins` or `NT AUTHORITY\SYSTEM`. Anything else is a finding.

## Detect rogue ownership

This script collects all privileged objects and flags any where the owner is not `Domain Admins` or `SYSTEM`.

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

If the output is empty, you're clean. If not — fix it.

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

Ownership drifts over time. Users who create objects become owners by default. Schedule the fix to run regularly.

**Important:** The account running this script needs the ability to take ownership and modify DACLs on privileged objects — effectively Domain Admin level access. The host executing it must be protected at the same tier as your domain controllers.

Use a **gMSA** (Group Managed Service Account) instead of storing credentials:

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

The gMSA password is managed by AD automatically (240-byte random, rotated every 30 days). No credentials to store, no passwords to rotate.

## Conclusion

Rogue object ownership is easy to overlook and easy to exploit. An attacker with `Owns` on a single privileged object can escalate to Domain Admin in three steps. Detect it, fix it, and schedule it so it stays fixed.
