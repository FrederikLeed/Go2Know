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

Who did what when? (why?) A post about Active Directory security events and finding the information using kustu query language.

This is a simple post, go [here](https://github.com/rod-trent/MustLearnKQL)  to learn more about KQL. Also, follow [Matt Zorich](https://twitter.com/reprise_99?s=20) on twitter for even more awesome security related kql content.

## Why do we need to know?

Knowing who changes group membership is important for several reasons. Firstly, it helps maintain accountability and responsibility within a group or organization. By keeping track of who adds or removes members from a group, it is easier to identify and address any issues that may arise due to unauthorized or inappropriate changes.

Secondly, knowing who changes group membership can also aid in the auditing and monitoring of group activities. This is particularly important for organizations that deal with sensitive or confidential information, where any unauthorized changes could have serious consequences.

Overall, having a clear understanding of who is responsible for managing group membership can help ensure that group activities are conducted in a transparent and secure manner.

## How do we get to know?

First, we need to enable auditing for 
[Audit Security Group Management](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-security-group-management)

## Simple KQL ![powershell](/assets/images/powershell.png){:width="30px"}

{% include codeHeader.html %}

```kusto
SecurityEvent
| where TimeGenerated > ago(7d) // timeframe
| where EventID in (4732,4733) //4732 member added, 4733 member removed
//| where TargetUserName contains "admins" //which group was changed
| where isnotempty( MemberName)
| project TimeGenerated, TargetUserName, SubjectUserName, Activity, MemberName, EventID
```
