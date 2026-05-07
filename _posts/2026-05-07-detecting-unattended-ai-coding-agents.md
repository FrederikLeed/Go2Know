---
title: "Detecting unattended AI coding agents with Defender XDR"
excerpt: "Three KQL queries — one each for Claude Code, OpenAI Codex CLI, and GitHub Copilot CLI — that surface AI agents executing shell commands on your endpoints without a human in the approval loop."
date: 2026-05-07
categories:
  - Security
tags:
  - Claude Code
  - OpenAI Codex
  - GitHub Copilot
  - Defender XDR
  - KQL
  - Advanced Hunting
toc: true
toc_label: "Contents"
toc_sticky: true
published: false
---

A few weeks ago I wrote about how I contain my own AI coding agent — containers, deny-by-default egress, the lot. That post was about how i run autonomous agents, contained. This one is the inverse: "is any AI agent running on endpoints in your environment, with no human in the approval loop" ?

Three of the most common AI coding agents — Claude Code, OpenAI Codex CLI, GitHub Copilot CLI — all support a fully autonomous mode where they execute shell commands without asking the user. Each one has a documented command-line signature for that mode, and Defender stores every process command line in the `DeviceProcessEvents` table. The queries below are written for Defender XDR Advanced Hunting and run unchanged in Sentinel — if your process telemetry lives somewhere else (Splunk, Elastic, CrowdStrike, SentinelOne), the logic is the same, only the field names change. Translate to whatever you've got.

Three queries, no baselining, no anomaly detection. Either the result is empty — every shell command those agents executed had a human approving it — or it isn't, and you have a conversation to have.

## Claude Code

Claude Code's default behaviour is to ask the user before every shell command, file edit, and network call. There are three documented ways to turn that off.

| Flag | Behaviour |
|------|-----------|
| `--dangerously-skip-permissions` | Legacy "Safe YOLO" flag. Skips all permission prompts. |
| `--permission-mode bypassPermissions` | Current canonical name, equivalent behaviour. |
| `--permission-mode auto` | Newer, classifier-decides. No prompts; a server-side classifier blocks actions it deems dangerous. |

Anthropic's own permission-modes documentation is unambiguous about the first two: *"bypassPermissions offers no protection against prompt injection or unintended actions."* The `auto` mode is positioned as a safer alternative — but from a SOC perspective it's still unattended execution.

The other modes (`default`, `acceptEdits`, `plan`, `dontAsk`) all still prompt the user before shell execution, so they aren't interesting for this question.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("claude", "claude.exe", "claude.cmd")
| where ProcessCommandLine has "--dangerously-skip-permissions"
    or ProcessCommandLine matches regex @"--permission-mode\s+(bypassPermissions|auto)\b"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## OpenAI Codex CLI

Codex's autonomy model is structured differently. The unattended signal is a **subcommand**, not a flag: `codex exec`.

OpenAI's non-interactive mode documentation describes it plainly: *"Codex exec runs Codex non-interactively (without the TUI or prompts)... Run as part of a pipeline (CI, pre-merge checks, scheduled jobs)."* That's the canonical CI/automation entry point — no TUI, no approval prompts.

A handful of flags layer extra autonomy on top and are worth catching as belt-and-braces signals:

- **`--full-auto`** — convenience alias for `-a on-failure --sandbox workspace-write`. Deprecated in newer versions but still works.
- **`--dangerously-bypass-approvals-and-sandbox`** (alias **`--yolo`**) — full bypass, no sandbox, no approvals. OpenAI's own docs label this *"EXTREMELY DANGEROUS. Intended solely for running in environments that are externally sandboxed."*
- **`--ask-for-approval never`** (or `-a never`) — disables approval prompts in any sandbox mode.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("codex", "codex.exe")
| where ProcessCommandLine matches regex @"\bcodex(\.exe)?\s+(exec|e)\b"
   or ProcessCommandLine has_any ("--full-auto", "--yolo", "--dangerously-bypass-approvals-and-sandbox")
   or ProcessCommandLine matches regex @"--ask-for-approval\s+never\b"
   or ProcessCommandLine matches regex @"\s-a\s+never\b"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## GitHub Copilot CLI

Copilot CLI needs two things to run unattended: non-interactive mode *and* an allow-all flag. The `-p`/`--prompt` flag alone is non-interactive but still prompts for tool approval. For true autonomous execution you need `--allow-all-tools` or `--allow-all`.

GitHub's own About-Copilot-CLI documentation doesn't pull punches: *"These options allow Copilot to execute commands needed to complete your request, without giving you the opportunity to review and approve those commands before they are run. While this streamlines workflows, and allows headless operation of the CLI, it increases the risk of unintended actions being taken that might result in data loss or corruption, or other security issues."*

GitHub's responsible-use guide calls this **"autopilot mode"**: *"Typically, when you use Copilot CLI in autopilot mode, you will grant it full permissions to allow it to complete a task autonomously, without requiring you to approve activity as it works on the task."*

This is the standalone `copilot` binary (npm `@github/copilot`), not the older `gh copilot` extension. The latter only suggests shell commands — it doesn't execute them — so it's not relevant here.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("copilot", "copilot.exe", "copilot.cmd")
| where ProcessCommandLine has_any ("--allow-all-tools", "--allow-all")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## Wrapping up

Three queries, fifteen minutes. Each one either returns hits — who, on what device, running what — or returns nothing. The queries don't depend on baselines or anomaly models; they answer the question on their own.

A word of warning before you read too much into a clean result, though: this only sees what Defender sees. Process telemetry from `DeviceProcessEvents` covers managed Windows, macOS, and Linux endpoints that are actually onboarded — and that is rarely the full picture of where developers run AI. WSL2 distributions are usually not enrolled, so a Claude or Codex session inside Ubuntu-on-Windows is invisible to this query. Linux servers and personal Linux dev machines often don't have the agent installed. Cloud VMs, lab boxes, BYOD laptops, containers on a workstation — same story. An empty result on a sizeable estate is more likely to be a coverage problem than a behaviour one. That's its own post.

The point isn't to ban any of these tools. It's to know how they're being used, by whom, and on which machines. That's where this kind of visibility starts.
