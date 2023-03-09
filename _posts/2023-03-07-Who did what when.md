---
title: "Who put who in which group?"
categories:
  - Hunting
author:
 - Frederik Leed
tags:
  - Microsoft
  - Security
  - KQL
layout: post  
---

Who added that user to that group? When? A post about Active Directory security events and finding the information using kustu query language.

This is a simple post, go [here](https://github.com/rod-trent/MustLearnKQL)  to learn more about KQL. Also, follow [Matt Zorich](https://twitter.com/reprise_99?s=20) on twitter for even more awesome security related kql content.

Check out this [intro to Kusto Query Language](https://www.youtube.com/watch?v=Pl8n6GaWEo0)  video from [John Savill](https://twitter.com/NTFAQGuy?s=20) out.

## Why do we need to know?

Knowing who changes group membership is important for several reasons. Firstly, it helps maintain accountability and responsibility within a group or organization. By keeping track of who adds or removes members from a group, it is easier to identify and address any issues that may arise due to unauthorized or inappropriate changes.

Secondly, knowing who changes group membership can also aid in the auditing and monitoring of group activities. This is particularly important for organizations that deal with sensitive or confidential information, where any unauthorized changes could have serious consequences.

Overall, having a clear understanding of who is responsible for managing group membership can help ensure that group activities are conducted in a transparent and secure manner.

## How do we get to know?

Remember, when a user is put in to a group or removed from a group, it is not an attribute on the user that is being changed, but the "member" attribute on a group.

First, we need make sure we have the corresponding auditlogs settings. [Audit Security Group Management](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-security-group-management)

>![Audit_GPO](/assets/images/Audit_security_group_mgmt.png){:width="500px"}

I would definitely reccomend looking at the [Microsoft Security baselines](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines) for auditing settings, in this case, specifically at the Domain Controller baseline. A friend of mine created this script to easily import various securitybaselines in your AD environment. [Import-MSFT-Baselines](https://github.com/SysAdminDk/Powershell-Scripts/blob/main/Active%20Directory/Import-MSFT-Baselines.ps1)

## Then we need to find the data

Now this is not a post about how to ship security logs to your log-store. You can use [this](https://pixelrobots.co.uk/2019/07/query-active-directory-security-events-using-azure-log-analytics-on-the-cheap/) as a guide to quickly get security logs from domain controllers into a LogAnalytics workspace.

-Other logs stores are fine, events are the same, query language will differ.

Here is a quick KQL query with a some filtering examples.

1. TimeGenerated will specify timeframe
2. EventID includes member added EventID 4732 and member removed EventID 4733
3. SubjectUserName will be the sAMAccountName of the user doing the action (Uncomment to include filter)
4. TargetUserName is the group being changed

If you do not edit the query, it will return every group having membership change the last 24 hours.

{% include codeHeader.html %}

```powershell
SecurityEvent
| where TimeGenerated > ago(1d) // timeframe
| where EventID in (4732,4733) //4732 member added, 4733 member removed
//| where SubjectUserName contains "adminuser01" //Who did the change
//| where TargetUserName contains "admins" //which group was changed
| project TimeGenerated, TargetUserName, SubjectUserName, Activity, MemberName, EventID
```
