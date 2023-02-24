---
title: "Member server inventory - local groups"
categories:
  - Windows
author:
 - Frederik Leed
tags:
  - Microsoft
  - Security
  - Powershell
layout: post  
---

Who has access to your servers?

## Why do we need to know?

Knowing the members of local groups on servers is important for several reasons, including:

Security: The members of local groups on servers can include user accounts and groups that have access to sensitive resources and data. By knowing who is a member of these groups, server administrators can ensure that only authorized personnel have access to these resources and that security policies are being enforced.

Troubleshooting: When troubleshooting issues on servers, it can be helpful to know which users and groups are members of certain local groups. This information can help administrators determine the cause of issues related to user permissions or access.

Compliance: Many organizations are required to comply with regulations related to data access and security. Knowing the members of local groups on servers can help organizations demonstrate compliance with these regulations by providing an audit trail of who has access to sensitive data.

In summary, understanding the membership of local groups on servers is an important aspect of server management, security, and compliance.

## The script! ![powershell](/assets/images/powershell.png){:width="30px"}

{% include codeHeader.html %}

```powershell
# Set the root OU for the search
$root = "OU=Servers,OU=Tier0,OU=adm,DC=domain,DC=com"

# Set the groups to query
$groups = "Administrators", "Remote Desktop Users"

# Loop through each computer in the search base
Get-ADComputer -SearchBase $root -Filter * -Property DNSHostname |
    # Filter out computers that do not have a valid WS-Management connection
    Where-Object { Test-WSMan -ComputerName $_.DNSHostname -ErrorAction SilentlyContinue } |
    ForEach-Object {
        # Get the computer name
        $computerName = $_.DNSHostname

        Invoke-Command -ComputerName $computerName -ScriptBlock {
        # Retrieve the members of each group using ADSI
            foreach ($group in $args) {
                # Connect to the local SAM database using ADSI
                $adsi = [ADSI]"WinNT://$env:computerName"
            
                # Get the group object
                $groupObject = $adsi.Children | Where-Object { $_.SchemaClassName -eq 'group' -and $_.Name -eq $group }

                # Get the members of the group
                if ($groupObject) {
                    $members = @($groupObject.Invoke("Members")) | ForEach-Object {
                        # Get the ADsPath property and remove the "WinNT://" prefix
                        $adsPath = $_.GetType().InvokeMember("ADsPath", 'GetProperty', $null, $_, $null)
                        $adsPath.Replace("WinNT://", "")
                    }
                }
                else {
                    # If the group does not exist, set the members to an empty array
                    $members = @()
                }
        
            # Create a custom object with the computer name, group name, and comma-separated list of group members
                [PSCustomObject] @{
                    PSComputerName = $env:computerName
                    GroupName = $group
                    Members = $Members -join ","
                }
            }
        } -ArgumentList @($groups)
    } | Export-Csv -Path C:\temp\t0LGroupMembers.csv -NoTypeInformation -NoClobber -Encoding UTF8
```
