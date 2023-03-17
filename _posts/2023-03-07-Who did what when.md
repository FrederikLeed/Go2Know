---
title: "Who did what to which object, when?"
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

In this blog post, we'll discuss how to track changes in Active Directory (AD) with multiple examples. This information can be crucial for identifying security incidents, troubleshooting issues, and meeting compliance requirements.

A post about Active Directory security events and finding the information using Kusto Query Language.

This is a simple post, go [here](https://github.com/rod-trent/MustLearnKQL)  to learn more about KQL. Also, follow [Matt Zorich](https://twitter.com/reprise_99?s=20) on twitter for even more awesome security related KQL content.

Make sure to check out this [intro to Kusto Query Language](https://www.youtube.com/watch?v=Pl8n6GaWEo0)  video from [John Savill](https://twitter.com/NTFAQGuy?s=20) out.

<!-- TOC start -->
- [Why do we need to know?](#why-do-we-need-to-know)
- [Common Changes in Active Directory](#common-changes-in-active-directory)
- [Enable audit logging](#enable-audit-logging)
- [Summary](#summary)
- [Example queries](#example-queries)
  - [User Account Creation and Deletion](#user-account-creation-and-deletion)
  - [Group Membership Modification (Addition/Removal)](#group-membership-modification-additionremoval)
  - [User Account Disable/Enable](#user-account-disableenable)
  - [Password Resets and Password Changes](#password-resets-and-password-changes)
  - [Organizational Unit (OU) Changes](#organizational-unit-ou-changes)
  - [Group Policy Changes](#group-policy-changes)
<!-- TOC end -->

## Why do we need to know?

Understanding who modifies Active Directory objects is crucial for several reasons. First and foremost, it helps maintain accountability and responsibility within an organization. By keeping track of who creates, modifies, or deletes AD objects, it becomes easier to identify and address any issues that may arise due to unauthorized or inappropriate changes.

Secondly, knowing who changes AD objects can also aid in auditing and monitoring the activities within the directory service. This is especially important for organizations that handle sensitive or confidential information, where any unauthorized modifications could have severe consequences.

In summary, having a clear understanding of who is responsible for managing Active Directory objects can help ensure that the directory service operates in a transparent and secure manner.

## Common Changes in Active Directory

In this section, we'll cover some of the most common changes that administrators make in Active Directory. These include:

1. **User Account Creation**: When a new employee joins the organization, administrators create a user account for them.
2. **User Account Deletion**: When an employee leaves the organization or their account is no longer needed, administrators delete the user account.
3. **Group Membership Modification**: Administrators may add or remove users from security or distribution groups based on changing access requirements or organizational structure.
4. **User Account Disable/Enable**: Administrators might need to disable user accounts temporarily, for instance, during an investigation or when an employee is on extended leave. Later, they might need to re-enable the account.
5. **Password Resets**: Administrators may need to reset user passwords for various reasons, such as when users forget their passwords or when a security incident requires a mass password reset.
6. **Organizational Unit (OU) Changes**: Administrators may create, modify, or delete OUs to reflect changes in the organizational structure or to manage permissions and Group Policy settings more effectively.
7. **Group Policy Changes**: Administrators often modify Group Policy Objects (GPOs) to enforce or update security settings, software installations, and other configurations.

## Enable audit logging

To track the changes mentioned previous section, you'll need to enable the following audit categories on your domain controllers. These categories are configured through Group Policy Management:

Account Management: This category includes events related to user account creation, deletion, and modification (enable/disable). It also covers events related to group membership changes.

Directory Service Changes: This category includes events related to the creation, modification, or deletion of Active Directory objects, such as Organizational Units (OUs) and Group Policy Objects (GPOs).

To enable these audit categories, follow these steps:

- Open the Group Policy Management Console on a domain controller or a computer with the Remote Server Administration Tools (RSAT) installed.
- Expand the Forest > Domains > YourDomain nodes in the left pane.
- Right-click on the Default Domain Controllers Policy and select Edit. This will open the Group Policy Management Editor.
- Navigate to Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies.
- Locate and configure the following audit policies:
  - Account Management:
    - Audit User Account Management: Set to Success
    - Audit Security Group Management: Set to Success
  - Directory Service Changes:
    - Audit Directory Service Changes: Set to Success

Audit Directory Service Changes determines whether the operating system generates audit events when changes are made to objects in Active Directory Domain Services (AD DS).
[Directory Service Changes](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-directory-service-changes)

Audit User Account Management determines whether the operating system generates audit events when specific user account management tasks are performed.
[User Account Management](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-user-account-management)

Audit Security Group Management determines whether the operating system generates audit events when specific security group management tasks are performed.
[Security Group Management](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-security-group-management)

These are just some of the available audit policies. To create a more comprehensive solution I would definitely reccomend looking at the [Microsoft Security baselines](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines) for auditing settings, in this case, specifically at the Domain Controller baseline.

Check out this script to easily import various Microsoft securitybaselines in your AD environment. [Import-MSFT-Baselines](https://github.com/SysAdminDk/Powershell-Scripts/blob/main/Active%20Directory/Import-MSFT-Baselines.ps1)

## Summary

Tracking changes in Active Directory is essential for maintaining a secure and well-managed IT environment. By monitoring events such as user account creation/deletion, group membership modifications, user account disable/enable, password resets, OU changes, and Group Policy changes, administrators can stay informed about the state of their AD environment, identify potential security threats, and meet compliance requirements.

## Example queries

Now this is not a post about how to ship security logs to your log store,  but to get started with Log Analytics as log store, you can use [this](https://pixelrobots.co.uk/2019/07/query-active-directory-security-events-using-azure-log-analytics-on-the-cheap/) as a guide to quickly get security logs from domain controllers into a LogAnalytics workspace.

> Other logs stores are fine, events are the same, but query language will differ.

Here are some KQL hunting queries for the examples mentioned in common changes section. These queries are designed to work with Azure Log Analytics, but you can adapt them to other platforms that support KQL. You can use these queries to hunt for specific events in your logs and investigate potential security incidents.

### User Account Creation and Deletion

{% include codeHeader.html %}

```powershell
SecurityEvent
| where EventID in (4720, 4726)
| extend AccountName = TargetUserName, AccountDomain = TargetDomainName
| extend Editor = SubjectUserName, EditorDomain = SubjectDomainName
| project TimeGenerated, Activity, AccountName , Editor
```

### Group Membership Modification (Addition/Removal)

{% include codeHeader.html %}

```powershell
SecurityEvent
| where EventID in (4728, 4729, 4732, 4733)
| extend GroupName = TargetUserName
| extend GroupDomain = TargetDomainName
| extend Editor = SubjectUserName
| extend EditorDomain = SubjectDomainName
| project TimeGenerated, Editor, GroupName , MemberName, Activity, EventID
```

### User Account Disable/Enable

{% include codeHeader.html %}

```powershell
SecurityEvent
| where EventID in (4722, 4725)
| extend AccountName = TargetUserName, AccountDomain = TargetDomainName
| extend Editor = SubjectUserName, EditorDomain = SubjectDomainName
| project TimeGenerated, Activity, AccountName, Editor
```

### Password Resets and Password Changes

{% include codeHeader.html %}

```powershell
SecurityEvent
| where EventID in (4724,4723)
| extend AccountName = TargetUserName, AccountDomain = TargetDomainName
| extend Editor = SubjectUserName, EditorDomain = SubjectDomainName
| project TimeGenerated, Activity, AccountName, Editor
```

### Organizational Unit (OU) Changes

{% include codeHeader.html %}

```powershell
SecurityEvent
| where TimeGenerated > ago(10d)
| where EventID in (5136, 5137, 5141)
| extend pEventData = parse_xml(EventData)
| extend ObjectClass = parse_json(tostring(parse_json(tostring(pEventData.EventData)).Data))[10].["#text"]
| extend GPODN = parse_json(tostring(parse_json(tostring(pEventData.EventData)).Data))[8].["#text"]
| extend GPDomain = parse_json(tostring(parse_json(tostring(pEventData.EventData)).Data))[6].["#text"]
| extend Editor = SubjectUserName, EditorDomain = SubjectDomainName
| where ObjectClass == "organizationalUnit"
| project TimeGenerated, Activity, tostring(GPODN), Editor
```

### Group Policy Changes

{% include codeHeader.html %}

```powershell
SecurityEvent
| where TimeGenerated > ago(10d)
| where EventID in (5136, 5137, 5141)
| extend pEventData = parse_xml(EventData)
| extend ObjectClass = parse_json(tostring(parse_json(tostring(pEventData.EventData)).Data))[10].["#text"]
| extend ObjectDN = parse_json(tostring(parse_json(tostring(pEventData.EventData)).Data))[8].["#text"]
| extend DSName = parse_json(tostring(parse_json(tostring(pEventData.EventData)).Data))[6].["#text"]
| where ObjectClass == "groupPolicyContainer"
| project TimeGenerated, EventID, tostring(GPODN = ObjectDN), tostring(GPDomain = DSName), Editor = SubjectUserName, EditorDomain = SubjectDomainName
```
