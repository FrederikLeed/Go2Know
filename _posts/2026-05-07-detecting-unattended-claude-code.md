---
title: "Detecting unattended Claude Code with Defender XDR"
excerpt: "One KQL query against DeviceProcessEvents tells you whether anyone on your estate is running Claude Code without a human in the approval loop."
date: 2026-05-07
categories:
  - Security
tags:
  - Claude Code
  - Defender XDR
  - KQL
  - Advanced Hunting
toc: true
toc_label: "Contents"
toc_sticky: true
published: false
---

A few weeks ago I wrote about how I contain my own AI coding agent — containers, deny-by-default egress, the lot. That post was about *my* environment. This is the inverse: I have a corporate estate to look after, and the question is whether anyone *else* is running an AI agent on a managed workstation, and if so, whether a human is approving its shell commands or not.

This is shadow AI visibility. It's a different problem from "should we allow Claude Code at all" — that's a policy question, and other people get to answer it. Mine is more practical: if it's running on my endpoints, I want to know whether a human is in the loop.

## The question worth asking first

Claude Code has several permission modes. The default prompts the user before any shell command runs, and a handful of intermediate modes (`acceptEdits`, `plan`, `dontAsk`) still require approval before shell execution. The interesting question for risk is whether any of the **no-prompt** modes are in use:

| Flag | Behaviour |
|------|-----------|
| `--dangerously-skip-permissions` | Legacy name, still works. No prompts. |
| `--permission-mode bypassPermissions` | Current name, same behaviour. |
| `--permission-mode auto` | Newer, classifier-decides, still no human prompts. |

If none of those flags are present, every shell command Claude ran was approved by a human clicking "yes". If one of them is present, Claude was free to run whatever it decided to run. Two very different operational pictures.

The well-publicised incidents — Wolak's October 2025 `rm -rf /` and the December 2025 Reddit `~/` wipe — happened in unattended mode. Not because the mode is broken; because that's what unattended means.

## Process telemetry has the answer

You don't need bash history forensics, you don't need to instrument the agent, you don't need to fingerprint shell snapshots. The flags are on the command line, and Defender records command lines for every process it sees. So the detection is a `DeviceProcessEvents` query and nothing more.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("claude", "claude.exe", "claude.cmd")
| where ProcessCommandLine has "--dangerously-skip-permissions"
    or ProcessCommandLine matches regex @"--permission-mode\s+(bypassPermissions|auto)\b"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

One thing worth calling out: `has_any` looks tempting here, but it doesn't work for the `--permission-mode` flags. KQL's `has` tokenises on whitespace, so `has "--permission-mode auto"` doesn't match the two-token phrase. The regex anchors flag and value together, which is what you actually want.

## Sanity-check first

A zero-result detection is only meaningful if you know your data covers the case. Run the baseline query alongside, so you can see whether anyone is using Claude at all:

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("claude", "claude.exe", "claude.cmd")
| summarize Runs=count(), Devices=dcount(DeviceName) by AccountName
| order by Runs desc
```

I ran both on our estate. Baseline came back with 8 distinct users and a few hundred runs over 30 days. Detection came back empty. That's the answer I was hoping for: people are using it, nobody is running it without approval prompts.

If your baseline is also empty — that's not necessarily good news. See below.

## What this doesn't cover

A few honest limitations:

- **Defender coverage.** This works on Windows, macOS, and Linux endpoints onboarded to Defender. WSL2 distributions are a common blind spot — they're usually not enrolled, so Claude running inside WSL is invisible to this query unless WSL has been explicitly onboarded.
- **What Claude actually did.** This tells you *how* the process was launched, not what it ran. A separate detection based on the bash shell-snapshot fingerprint gets at actual command execution; that's a different post.
- **Agent SDK use.** Scripts built on the Claude Agent SDK spawn the `claude` binary as a child process, so they show up in the same `DeviceProcessEvents` data. Distinguishing scripted from interactive use needs parent-process analysis, which I'll leave for another time.

## Wrapping up

Two queries, fifteen minutes of work, full visibility on whether anyone is letting an AI agent run shell commands on your endpoints without explicit approval. Run both. If the baseline shows nothing on a sizeable estate, ask why your endpoints aren't reporting `DeviceProcessEvents` for `claude` — that's the more interesting finding. If the detection shows something, you have a conversation to have with whoever owns that workstation.

The point isn't to ban the tool. It's to know how it's being used.
