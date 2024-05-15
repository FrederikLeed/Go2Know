---
title: "Using PowerShell to Get Members of Privileged Groups Across All Domains"
categories:
  - Administration
author:
  - Frederik Leed
tags:
  - PowerShell
  - Active Directory
  - Security
layout: post
---

In this blog post, we will explore a PowerShell script designed to retrieve members of specific privileged and exclusive groups across all domains in an Active Directory (AD) forest. This script can be incredibly useful for system administrators and security professionals who need to audit group memberships and ensure that only authorized users have access to sensitive groups.

A post about obtaining details of users in critical AD groups using a PowerShell script.

## Why Use This Script?

Tracking members of privileged groups in an AD environment is crucial for maintaining security and compliance. Here are a few reasons why this script is beneficial:

1. **Security Audits**: Regularly auditing group memberships helps ensure that only authorized users have elevated privileges.
2. **Compliance**: Many regulations require organizations to keep track of who has access to critical systems and data.
3. **Accountability**: Knowing who belongs to privileged groups helps maintain accountability within the organization.
4. **Incident Response**: In the event of a security incident, understanding group memberships can aid in the investigation.

## Script Overview

The provided PowerShell script performs the following tasks:

- Defines a list of privileged and exclusive groups.
- Retrieves the current AD forest and iterates through each domain.
- Queries the specified groups for their members, focusing on user objects.
- Collects and stores details of each user, including their group memberships.
- Exports the results to a CSV file for further analysis.

Here is the full script:

```powershell
# PowerShell script to get members of specific groups and their attributes across all domains

# Define privileged and exclusive groups
$AdminGroups = @(
    "Account Operators", "Administrators", "Backup Operators", "Cert Publishers",
    "DNSAdmins", "Domain Admins", "Key Admins", "Print Operators", "Replicator",
    "Server Operators", "Network Configuration Operators",
    "Incoming Forest Trust Builders", "Domain Controllers", "Group Policy Creator Owners",
    "Read-only Domain Controllers", "Exchange Servers"
)
$ExclusiveGroups = @(
    "Enterprise Admins", "Enterprise Key Admins", "Schema Admins"
)

# Initialize result hashtable
$MemberDetails = @{}

# Get the current forest and process each domain
$forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
foreach ($domain in $forest.Domains) {
    Write-Host "Processing domain: $($domain.Name)"

    # Determine groups to query based on domain
    $groupsToQuery = $AdminGroups
    if ($domain.Name -eq $forest.RootDomain.Name) {
        $groupsToQuery += $ExclusiveGroups
    }

    foreach ($group in $groupsToQuery) {
        try {
            # Get the group object
            $adGroup = Get-ADGroup -Filter "Name -eq '$group'" -Server $domain.Name -ErrorAction Stop
            # Get members of the group, filter for users only
            $members = Get-ADGroupMember -Identity $adGroup -Recursive -Server $domain.Name -ErrorAction Stop | Where-Object {$_.objectClass -eq "User"}

            foreach ($member in $members) {
                $userKey = $member.DistinguishedName
                if (-not $MemberDetails[$userKey]) {
                    # Initialize user details and group list
                    $MemberDetails[$userKey] = @{
                        samAccountName = $member.samAccountName
                        displayName    = $member.Name
                        groups         = New-Object System.Collections.ArrayList
                    }
                }
                [void]$MemberDetails[$userKey].groups.Add($group)
            }
        } catch {
            Write-Warning "Could not process group '$group' in domain '$($domain.Name)': $_"
        }
    }
}

# Output the results
$MemberDetails.Keys | ForEach-Object {
    $user = $MemberDetails[$_]
    [PSCustomObject]@{
        DistinguishedName = $_
        samAccountName    = $user.samAccountName
        DisplayName       = $user.displayName
        Groups            = $user.groups -join ', '
    }
} | Out-GridView
#} | Export-Csv -Path "PrivilegedGroupMembers.csv" -NoTypeInformation

##Write-Host "Output has been saved to 'PrivilegedGroupMembers.csv'"
```

## How to Use the Script

1. **Prerequisites: Ensure you have the necessary permissions to query AD groups and members. You may need to run the script with elevated privileges.
2. **Run the Script: Execute the script in a PowerShell environment on a machine that has access to your AD forest.
3. **Review the Output: The script will generate a CSV file named PrivilegedGroupMembers.csv in the current directory. This file contains details of the users and their group memberships.

## Conclusion

By using this PowerShell script, administrators can efficiently gather information about members of critical AD groups, enhancing their ability to monitor and secure their environment. Regular audits with this script can help maintain a secure and well-managed Active Directory infrastructure.