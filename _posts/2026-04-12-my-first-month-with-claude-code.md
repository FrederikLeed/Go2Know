---
title: "Building an Isolated AI Agent Architecture with Claude Code"
excerpt: "How I built a self-hosted, per-project Docker environment for Claude Code — and why isolation, memory, and multi-device access matter."
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

I've been using AI coding agents for a few months now — ChatGPT Pro, GitHub Copilot, and eventually Claude Code. They're all useful in different ways, but they all share the same problem: they run on your machine with your permissions, they forget everything between sessions, and you can't manage multiple agents doing different work.

I'm a security consultant. I work on multiple customer projects simultaneously, each with sensitive data that shouldn't bleed into the other. I needed an architecture that treats AI agents the way I treat admin workstations — isolated, segmented, and auditable.

So I built one.

## The problems

These are the problems I ran into with every AI agent setup I tried, and what my architecture solves for each:

### 1. No isolation between projects

When an AI agent runs on your workstation, it can see everything. Every repo, every file, every credential. If you're working on Customer A's security assessment and switch to Customer B, the agent carries context — and access — across both.

**Solution:** Each project gets its own Docker container. The agent only sees its own workspace. Customer A's data is physically separated from Customer B's.

### 2. No memory across sessions

Every time you start a new chat, you start from zero. You re-explain your project, your conventions, your preferences. The agent rediscovers the codebase every time.

This is a well-known gap — even [OpenHands](https://github.com/OpenHands/OpenHands) (70k+ stars, the largest open-source AI coding agent) has this as a documented weakness. Each conversation gets a fresh container with no persistent state.

**Solution:** Persistent memory volumes that survive container restarts. Claude Code's memory directory (`/home/claude/.claude`) is bind-mounted from the host. Project knowledge, user preferences, and working context carry over between sessions automatically.

### 3. No blast radius control

An AI agent that can write and execute code can also delete files, install packages, and modify system configuration. If it goes wrong, the blast radius is your entire workstation.

**Solution:** Container isolation. If an agent does something destructive, it only affects its own container. Your host, your other projects, and your other agents are untouched.

### 4. No file exchange with the agent

Most agent setups don't have a clean way to give files to the agent or get files out. You end up copy-pasting, committing to git, or manually transferring.

**Solution:** A `/shared` volume mounted on the host and in every container. Drop a file into `/shared` from your workstation, and the agent can read it immediately. Agents can also pass files to each other through the same volume.

### 5. No host protection

An agent running on your workstation can reach everything your user account can — network shares, internal APIs, production systems. That's not a theoretical risk. Prompt injection, malicious MCP servers, or a compromised skill store could turn that access into an attack path.

**Solution:** The container has limited host access and limited network connectivity. It can reach the internet for git operations and API calls, but it can't reach your internal network by default. The roadmap includes deny-by-default egress policies inspired by [NemoClaw](https://www.nvidia.com/en-us/ai/nemoclaw/) — per-binary network allowlisting, policy-as-code, drift detection.

### 6. No credential management

Storing API keys or personal access tokens inside agent environments is a recipe for credential leakage. Especially when the agent can read its own config files.

**Solution:** OAuth device flow per container. Claude Code authenticates via `gh device login` — no stored tokens, no API keys. The credential exists only in memory for the duration of the session.

### 7. No fleet management

Once you have more than two or three agent containers running, you need a way to see what's running, start and stop instances, and get into a terminal without remembering container IDs.

**Solution:** [claude-manager](https://github.com/FrederikLeed/claude-manager) — a web UI for managing Claude Code containers. Create, start, stop, remove, terminal access, activity logs, file upload to shared storage. One dashboard for all your agents.

### 8. Single-device access

AI coding agents typically run in a terminal on one machine. If you start a session on your workstation and want to continue on your laptop — or check progress from your phone — you're out of luck.

**Solution:** claude-manager uses shared tmux sessions served through a web terminal (xterm.js). Connect from any browser on any device and drop into the same running session with full context.

### 9. Inconsistent environments

"Works on my machine" is bad enough with regular development. With AI agents, inconsistent environments mean inconsistent behavior — different tools installed, different versions, different capabilities.

**Solution:** A single Docker base image ([claude-workspace](https://github.com/FrederikLeed/claude-workspace)) with a known set of tools. Every agent container starts from the same image with the same capabilities.

## The architecture

```
┌─────────────────────────────────────────────┐
│  Docker Host                                │
│                                             │
│  ┌──────────────┐  ┌──────────────┐         │
│  │ claude-mgr   │  │ Project A    │         │
│  │ (web UI)     │  │ container    │         │
│  │ :3000        │  │              │         │
│  └──────┬───────┘  └──────────────┘         │
│         │          ┌──────────────┐         │
│         ├──────────│ Project B    │         │
│         │          │ container    │         │
│         │          └──────────────┘         │
│         │          ┌──────────────┐         │
│  Docker │          │ Project C    │         │
│  socket │          │ container    │         │
│         │          └──────────────┘         │
│         │                                   │
│  ┌──────┴───────────────────────────────┐   │
│  │  Shared volumes                      │   │
│  │  /shared          (file exchange)    │   │
│  │  /project-memory  (per-project)      │   │
│  │  /home/claude/.claude (agent memory) │   │
│  └──────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
```

**claude-manager** communicates with the Docker engine via the socket to create and manage sibling containers. Each project container is isolated — its own filesystem, its own network namespace, its own Claude Code session. The shared volumes provide controlled data exchange without breaking isolation.

Docker is the source of truth for container state. claude-manager's SQLite database only stores supplemental metadata — human-readable names, tags, notes, activity history.

## Is this unique?

I looked around before writing this, and I couldn't find an existing solution that combines all of these pieces. Here's what's out there:

- **OpenHands** — per-conversation Docker isolation and a web UI, but no persistent memory across sessions. Every conversation starts fresh.
- **AgentManager** — orchestrates up to 100 concurrent agents, but focused on parallel execution, not persistent per-project workspaces.
- **HolyClaude** — web UI with multiple AI CLIs, but runs everything in one monolithic container. No isolation.
- **ClaudeBox** — per-project Docker images, but CLI-only, no web UI, no multi-device access.
- **NemoClaw** — excellent security sandbox for a single agent, but not a workspace management layer.

The individual pieces all exist — Docker isolation, memory layers, web UIs, multi-device access. The combination of persistent, isolated, per-project agent workspaces with a management UI and multi-device access doesn't seem to exist elsewhere.

## Security concerns I'm still working on

This architecture handles isolation and blast radius. But there are bigger questions I'm still thinking about.

### Supply chain risk

The MCP server / skill store ecosystem is a supply chain attack waiting to happen. Third-party tools that an AI agent can discover and install autonomously — that's `npm install` with even less human review. One compromised skill, and the agent is running attacker code with whatever permissions it has.

Container isolation helps, but it's not enough. I want deny-by-default egress: the agent can only reach explicitly allowlisted endpoints. NemoClaw has the right model — per-binary network policies, policy-as-code, drift detection. That's next on my roadmap for claude-manager.

### Customer data and compliance

I use Claude to analyze AD security assessment data — and it produces significantly better analysis because of it. But the compliance question is real: what happens to the data the AI processes? Is it stored? Used for training?

My current position: customer consent is required before their data goes into any AI tool. But where I want to end up is **local processing** — running models on my own hardware where data never leaves my network. That's the path I started on with OpenClaw, and it's still the goal.

## What's next

- **Network policies** — deny-by-default egress on agent containers, NemoClaw-inspired
- **Local model processing** — running models on-premises for customer data
- **Multi-agent orchestration** — coordinated agents working on different parts of the same project via shared context

The repos are public if you want to look at the implementation:
- [claude-workspace](https://github.com/FrederikLeed/claude-workspace) — the Docker base image
- [claude-manager](https://github.com/FrederikLeed/claude-manager) — the management UI
