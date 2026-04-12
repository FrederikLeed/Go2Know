---
title: "Who Has Access to Your Servers"
excerpt: "Audit local group memberships across your server fleet — because you need to know who has admin and RDP access."
date: 2023-02-23
last_modified_at: 2023-02-23
categories:
  - Windows
tags:
  - PowerShell
  - Security
toc: true
toc_label: "Contents"
toc_sticky: true
---

"Who has local admin on our servers?" If you can't answer that question in under a minute, you have a visibility problem.

Local group memberships on servers are one of the most overlooked attack surfaces. Someone adds a service account to the local Administrators group during a weekend migration, and it stays there for years. A contractor gets Remote Desktop access "temporarily" and nobody removes it.

## The script

This pulls the members of local Administrators and Remote Desktop Users from every server in an OU. It uses WinRM, so no agent required — just connectivity.

```powershell
$root = "OU=Servers,OU=Tier0,OU=adm,DC=domain,DC=com"
$groups = "Administrators", "Remote Desktop Users"

Get-ADComputer -SearchBase $root -Filter * -Property DNSHostname |
    Where-Object { Test-WSMan $_.DNSHostname -ErrorAction SilentlyContinue } |
    ForEach-Object {
        $computer = $_.DNSHostname
        Invoke-Command -ComputerName $computer -ScriptBlock {
            foreach ($group in $args) {
                $adsi = [ADSI]"WinNT://$env:computerName"
                $groupObj = $adsi.Children | Where-Object {
                    $_.SchemaClassName -eq 'group' -and $_.Name -eq $group
                }
                $members = if ($groupObj) {
                    @($groupObj.Invoke("Members")) | ForEach-Object {
                        $_.GetType().InvokeMember("ADsPath", 'GetProperty', $null, $_, $null) -replace "WinNT://", ""
                    }
                } else { @() }

                [PSCustomObject]@{
                    PSComputerName = $env:computerName
                    GroupName      = $group
                    Members        = $members -join ","
                }
            }
        } -ArgumentList @($groups)
    } | Export-Csv "ServerLocalGroupMembers.csv" -NoTypeInformation -Encoding UTF8
```

Adjust `$root` to match your OU structure. Add more groups to `$groups` if you want to audit Hyper-V Administrators, Event Log Readers, or other local groups.

## What to look for

Review the CSV for anything unexpected:

- **Service accounts in Administrators** — should be removed and replaced with proper delegation or gMSA
- **Named user accounts** — nobody should have personal admin access to servers
- **Stale domain groups** — groups that existed for a project that ended two years ago
- **Missing entries** — servers where the expected admin group is not present

Run this regularly. Local group memberships drift, and there's no built-in way to detect it.
