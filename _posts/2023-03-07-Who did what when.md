---
title: "Tracking Changes in Active Directory with KQL"
excerpt: "Who changed what, and when? KQL queries for the most common AD change events."
date: 2023-03-07
last_modified_at: 2023-03-07
categories:
  - Hunting
tags:
  - KQL
  - Active Directory
  - Security
toc: true
toc_label: "Contents"
toc_sticky: true
---

Someone changed a GPO on Friday and now half the org is locked out. A service account was added to Domain Admins and nobody knows who did it. Sound familiar?

Active Directory logs every change — if you have auditing enabled and know where to look. This post covers the audit settings you need and KQL queries for the most common scenarios.

If you're new to KQL, go through [MustLearnKQL](https://github.com/rod-trent/MustLearnKQL) and watch [John Savill's KQL intro](https://www.youtube.com/watch?v=Pl8n6GaWEo0).

## Enable audit logging

None of this works unless you enable the right audit policies on your domain controllers. Configure these via Group Policy on the Default Domain Controllers Policy:

**Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration:**

| Audit Policy | Setting | What it covers |
|---|---|---|
| [Audit User Account Management](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-user-account-management) | Success | User create, delete, enable, disable, password reset |
| [Audit Security Group Management](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-security-group-management) | Success | Group membership add/remove |
| [Audit Directory Service Changes](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-directory-service-changes) | Success | OU and GPO modifications |

For a comprehensive audit policy, use the [Microsoft Security Baselines](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines) — specifically the Domain Controller baseline.

## KQL queries

These queries work with Azure Log Analytics / Sentinel. Other log stores use the same event IDs but different query languages.

### User account creation and deletion

```kql
SecurityEvent
| where EventID in (4720, 4726)
| extend AccountName = TargetUserName
| extend Editor = SubjectUserName
| project TimeGenerated, Activity, AccountName, Editor
```

### Group membership changes

```kql
SecurityEvent
| where EventID in (4728, 4729, 4732, 4733)
| extend GroupName = TargetUserName
| extend Editor = SubjectUserName
| project TimeGenerated, Editor, GroupName, MemberName, Activity, EventID
```

### User account enable / disable

```kql
SecurityEvent
| where EventID in (4722, 4725)
| extend AccountName = TargetUserName
| extend Editor = SubjectUserName
| project TimeGenerated, Activity, AccountName, Editor
```

### Password resets and changes

```kql
SecurityEvent
| where EventID in (4724, 4723)
| extend AccountName = TargetUserName
| extend Editor = SubjectUserName
| project TimeGenerated, Activity, AccountName, Editor
```

### OU changes

```kql
SecurityEvent
| where EventID in (5136, 5137, 5141)
| extend pEventData = parse_xml(EventData)
| extend ObjectClass = parse_json(tostring(parse_json(tostring(pEventData.EventData)).Data))[10].["#text"]
| extend OUDN = parse_json(tostring(parse_json(tostring(pEventData.EventData)).Data))[8].["#text"]
| extend Editor = parse_json(tostring(parse_json(tostring(pEventData.EventData)).Data))[3].["#text"]
| where ObjectClass == "organizationalUnit"
| project TimeGenerated, Activity, tostring(OUDN), Editor
```

### GPO changes

```kql
let pattern = @'\{([^}]*)\}';
SecurityEvent
| where EventID in (5136, 5137, 5141)
| extend pEventData = parse_xml(EventData)
| extend ObjectClass = parse_json(tostring(parse_json(tostring(pEventData.EventData)).Data))[10].["#text"]
| where ObjectClass == "groupPolicyContainer"
| extend ObjectDN = parse_json(tostring(parse_json(tostring(pEventData.EventData)).Data))[8].["#text"]
| extend DSName = parse_json(tostring(parse_json(tostring(pEventData.EventData)).Data))[6].["#text"]
| extend Editor = tostring(parse_json(tostring(parse_json(tostring(pEventData.EventData)).Data))[3].["#text"])
| extend GPOID = extract("\\{([^}]*)\\}", 1, toupper(ObjectDN))
| project TimeGenerated, EventID, GPOID, tostring(GPDomain = DSName), Editor
```

## Conclusion

These queries cover the changes you'll investigate most often. Set them up as saved queries or analytics rules in Sentinel, and you'll have answers in seconds instead of hours.
