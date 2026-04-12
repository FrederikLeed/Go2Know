---
title: "My First Month with Claude Code — An AD Security Consultant's Perspective"
excerpt: "How I went from ChatGPT to a self-hosted AI agent workflow, what I've built with it, and why the security implications keep me up at night."
date: 2026-04-12
last_modified_at: 2026-04-12
categories:
  - Infrastructure
tags:
  - Claude Code
  - Docker
  - Automation
  - Security
toc: true
toc_label: "Contents"
toc_sticky: true
published: false
---

A customer called me about a dead domain controller. It had been offline for 62 hours after a Patch Tuesday reboot went sideways. 35 minutes later the DC was back online, I had a full incident report with root cause analysis, timeline, remediation steps, and follow-up actions — and I hadn't written a single line of it myself.

That's what working with an AI agent looks like in practice. This post is about how I got there, what I've built around it, and the security concerns that come with giving an AI access to real infrastructure work.

## The journey to Claude Code

I started with **ChatGPT Pro** about six months ago. Used it for sparring on ideas and having it write PowerShell scripts. It was useful but disconnected — I'd copy-paste code back and forth, explain context manually, and lose the thread between sessions.

Then I moved to **GitHub Copilot Pro** in VS Code. Better — it could see my code, suggest completions, and interact with files directly. But I felt limited by having to approve every single action. I couldn't tell it "go figure this out" and walk away.

I looked into **OpenClaw** (now NemoClaw) — the open-source agent framework from NVIDIA. The idea of a self-hosted, restricted AI agent was exactly what I wanted. But I didn't have the hardware to run local models at a useful quality level. That's still on my roadmap.

Then I found **Claude Code**. It clicked because I could treat it the way I wanted to treat OpenClaw — as an autonomous agent that I could restrict, isolate, and point at real work. Not a chatbot I paste things into, but an agent that reads my repos, runs scripts, analyzes output, and produces deliverables.

## How I actually use it

Most of my work starts with Claude now. The typical flow:

1. **Sparring** — I start in Claude chat to think through a problem. Architecture decisions, script design, approach.
2. **Building** — Claude Code writes the scripts, creates the files, commits to git. I review and steer.
3. **Analysis** — Script output goes back to Claude. It processes the data, finds patterns, correlates across sources.
4. **Reporting** — Claude writes the report. Not a template fill — an actual analysis with evidence, recommendations, and follow-up actions.

The key difference from Copilot: Claude understands the full context of what I'm working on. When I ask a question, it knows which repo I'm in, what the project does, what I've already tried. It can decide that more questions need answering before it gives me a response.

### The dead DC

A customer had a domain controller that went offline after patching. NTDS, DNS, KDC, DFSR — everything down. The other two DCs in the domain kept things running, but a third of their DC capacity was gone.

I asked Claude to write a triage script. It produced an 11-section diagnostic that ran remotely via WinRM — service state, NTDS registry, event logs from five sources, DCDiag, repadmin, database integrity, SYSVOL, FSMO roles, port connectivity to other DCs, recent patches, and disk space. One script, one execution, all the data collected and pulled back to my management server.

Claude analyzed the output and identified the root cause within seconds: the server had booted into Safe Mode. The `bcdedit` safeboot flag was set, NTDS couldn't start, and everything that depends on it cascaded down. One command to remove the flag, one reboot, and the DC was back.

Then Claude wrote the incident report — executive summary, service state comparison, full timeline with event IDs, root cause analysis, step-by-step remediation, risk assessment, and follow-up actions. Seven sections, fully detailed, with references to specific event IDs and KB numbers.

35 minutes from "the DC is down" to "here's your report." I wouldn't have been able to write that report in 35 minutes even if I already knew the root cause.

### Security assessments at scale

The biggest impact has been on my AD security assessment workflow. I built a toolkit ([ad-security-scan](https://github.com/FrederikLeed/ad-security-scan)) that collects data from eight different tools — SharpHound, PingCastle, AzureHound, PSPKI, password quality analysis, Maester, Conditional Access coverage, and SYSVOL policies. The analysis phase runs 60+ security queries against a BloodHound graph database.

The amount of data that comes out of a single assessment is massive. Hundreds of findings across ACL abuse, Kerberos attacks, certificate vulnerabilities, credential hygiene, delegation chains, hybrid identity risks, and M365 configuration. As a human, I physically cannot process all of that data at the same level of detail. I'd have to pick the top 10 findings and write up what I can in the time I have.

Claude reads all of it. Every data source, every finding, cross-referenced. It writes a full security report with findings grouped by severity, mapped to attack scenarios, with specific affected objects, detection guidance, and remediation steps. It generates an executive PowerPoint and a technical Word document. The level of detail in those reports is something I could never justify spending the time on manually.

## The setup — isolation matters

I don't just run Claude Code on my workstation. I built a Docker-based environment called [claude-workspace](https://github.com/FrederikLeed/claude-workspace) — each project gets its own isolated container with:

- **Limited host access** — the container only sees its own workspace and shared volumes
- **Shared memory** — a `/shared` volume for cross-container file exchange and a persistent memory directory so Claude retains context across sessions
- **Per-project focus** — one container, one project. The agent isn't distracted by unrelated work, and it can't accidentally touch something it shouldn't

I also built [claude-manager](https://github.com/FrederikLeed/claude-manager) — a web UI for managing these containers. Create, start, stop, terminal access, activity logs. The goal is to manage a fleet of focused agents, each working on their own thing.

Having an agent focused on one thing at a time makes a real difference. It stays in context, doesn't get confused by unrelated code, and delivers more precise results.

## The security concerns

I'm a security consultant. I think about risk for a living. And AI agents introduce risks that most people aren't thinking about yet.

### Autonomous code execution

Claude Code can write and execute code. That's the whole point — but it's also the biggest risk. An agent that can install packages, run scripts, and modify files is an agent that can be tricked into running something malicious.

The skill store / MCP server ecosystem is a supply chain attack waiting to happen. Third-party tools that an AI agent can discover and install autonomously? That's `npm install` with even less human review. One compromised skill, and the agent is running attacker code with whatever permissions it has.

This is why isolation matters. Limited network access, limited host access, no ability to reach production systems from the container. The NemoClaw project from NVIDIA had the right idea — deny-by-default egress, per-binary allowlisting, policy-as-code. I'm working on bringing that model to my claude-manager setup.

### Customer data and compliance

Here's the uncomfortable truth: I've fed customer AD data into Claude. Assessment results, security findings, environment details. It produces better analysis because of it. But I'm not entirely sure where I stand on compliance.

The question isn't whether the AI is useful — it clearly is. The question is: what happens to the data? How does the AI provider process it? Is it used for training? Is it stored? Can it be subpoenaed?

For me, the answer is customer consent. If the customer agrees that their data can be processed by an AI tool as part of the assessment, I'm comfortable. But I want more than that — I want **local processing**. Running the model on my own hardware, where data never leaves my network. That's the OpenClaw / NemoClaw path I started on, and it's still where I want to end up.

Until then, I treat AI-processed customer data the same way I treat any third-party tool: with explicit consent and clear boundaries about what goes in and what doesn't.

### What I'd tell a skeptic

If a fellow security professional tells me "you're giving an AI access to everything" — I'd say: no, I'm not. I'm giving it access to a segmented, isolated container with limited network connectivity and no path to production. The same principles we apply to admin workstations and jump servers apply here.

The conversation isn't "should we use AI agents" — it's "how do we use them safely." Network segmentation, least privilege, deny-by-default egress, audit logging, and explicit data handling agreements. We already know how to do this. We just need to apply it to a new type of tool.

## What's next

- **Network policies** — deny-by-default egress on agent containers, inspired by NemoClaw
- **Local model processing** — running models on my own hardware for customer data
- **Multi-agent orchestration** — multiple Claude instances working on different parts of the same project, coordinated through shared context

One month in, and Claude has already changed how I work. Not because it's magic — but because it can process more data, stay more focused, and produce more detailed output than I can alone. The security model around it is still a work in progress, but that's the interesting part.
