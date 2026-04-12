---
title: "Auditing Privileged Group Members Across All Domains"
excerpt: "A PowerShell script that pulls members of all privileged groups across every domain in your forest."
date: 2024-05-13
last_modified_at: 2024-05-13
categories:
  - Administration
tags:
  - PowerShell
  - Active Directory
  - Security
toc: true
toc_label: "Contents"
toc_sticky: true
---

"Who is in Domain Admins?" Easy to answer. "Who is in Domain Admins, Enterprise Admins, Schema Admins, Account Operators, Backup Operators, Server Operators, and every other privileged group — across all five domains in the forest?" That's a different question.

Most environments have multiple domains, and privileged groups that nobody checks. Enterprise Admins and Schema Admins only exist in the forest root. Operator groups exist in every domain but rarely get audited. This script covers all of them.

## The script

It iterates through every domain in the forest, queries all built-in privileged groups, and exports the members to CSV with their group memberships.

Regular domain user permissions are sufficient — no admin rights needed.

```powershell
# Groups that exist in every domain
$AdminGroups = @(
    "Account Operators", "Administrators", "Backup Operators", "Cert Publishers",
    "DNSAdmins", "Domain Admins", "Domain Controllers", "Group Policy Creator Owners",
    "Key Admins", "Print Operators", "Read-only Domain Controllers", "Replicator",
    "Server Operators", "Network Configuration Operators"
)

# Groups that only exist in the forest root domain
$ExclusiveGroups = @(
    "Enterprise Admins", "Enterprise Key Admins", "Schema Admins",
    "Incoming Forest Trust Builders"
)

$MemberDetails = @{}
$forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

foreach ($domain in $forest.Domains) {
    Write-Host "Processing: $($domain.Name)"
    $groupsToQuery = if ($domain.Name -eq $forest.RootDomain.Name) {
        $AdminGroups + $ExclusiveGroups
    } else { $AdminGroups }

    $netbios = (Get-ADDomain $domain.Name).NetBIOSName

    foreach ($group in $groupsToQuery) {
        try {
            $adGroup = Get-ADGroup -Filter "Name -eq '$group'" -Server $domain.Name -ErrorAction Stop
            $members = Get-ADGroupMember $adGroup -Recursive -Server $domain.Name -ErrorAction Stop |
                Where-Object objectClass -eq "User"

            foreach ($member in $members) {
                $key = $member.DistinguishedName
                if (-not $MemberDetails[$key]) {
                    $MemberDetails[$key] = @{
                        samAccountName = $member.samAccountName
                        displayName    = $member.Name
                        groups         = [System.Collections.ArrayList]::new()
                    }
                }
                [void]$MemberDetails[$key].groups.Add("$netbios\$group")
            }
        } catch {
            Write-Warning "Could not process '$group' in '$($domain.Name)': $_"
        }
    }
}

$MemberDetails.Keys | ForEach-Object {
    $user = $MemberDetails[$_]
    [PSCustomObject]@{
        DistinguishedName = $_
        samAccountName    = $user.samAccountName
        DisplayName       = $user.displayName
        Groups            = $user.groups -join ', '
    }
} | Export-Csv "PrivilegedGroupMembers.csv" -NoTypeInformation
```

## What to look for

The CSV will show you every user and which privileged groups they're in. Look for:

- **Accounts in multiple privileged groups** — usually a sign of over-provisioning
- **Service accounts in operator groups** — should be removed and replaced with proper delegation
- **Empty groups that should be empty** — Schema Admins, Enterprise Admins (only needed temporarily)
- **Groups that shouldn't have members at all** — Backup Operators and Print Operators should be empty on most environments

## Conclusion

Run this as part of your regular access reviews. Privileged group memberships creep — people get added during projects and never removed. A CSV export once a quarter takes five minutes and keeps you honest.
