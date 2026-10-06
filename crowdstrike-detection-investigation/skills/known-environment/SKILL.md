---
name: "known-environment"
description: "Reference the known-benign environment context for MerchantE Falcon investigations: authorized software, known host types, in-house tools, and common false-positive patterns. Use during detection investigation to shortcut recognized patterns, and update it when a new benign tool, host type, or pattern is confirmed. Entries lower effort but never authorize auto-clearing without verification."
license: "MIT"
compatibility: "Companion to the investigate-detection skill. No MCP tools required to read; updates follow the Learn step of an investigation."
metadata:
  author: "Homam Zituni"
  version: "1.0.0"
---

# Known Environment Context

## Overview

This skill holds MerchantE's known-benign environment knowledge used during CrowdStrike Falcon detection investigations. The **investigate-detection** skill consults these entries during Steps 1, 5, 6, and 7 to shortcut recognized patterns. Every entry is a verification aid, not a clearance: you must still verify the process tree and network activity each time, because hashes change between builds and attackers reuse known-good filenames and paths.

## When to Use

- During an investigation, to recognize an authorized vendor, a known host type, an in-house tool, or a common false-positive pattern.
- After an investigation, to record a newly confirmed benign tool/host/pattern (the "Learn" step).

## Update Rules (Learn Step)

- Add or update an entry only once benign nature is **confirmed** by evidence and/or owner confirmation — not on suspicion alone.
- Place the entry in the correct section: Authorized Software, Known Host Types, Known In-House Tools, or Common False Positive Patterns.
- Include the confirming SEC ticket reference (e.g. SEC-XXXX) when one exists — as a text citation; this skill does not query or create tickets.
- Preserve the "still verify each time" discipline in the wording — the entry lowers effort, it never authorizes auto-closing without verification.
- Updating this file is allowed without approval. Modifying Falcon alerts is prohibited.

## Authorized Software (verify process tree is normal before clearing)

- **TeamViewer** — Authorized org-wide for remote support. Expected parent: TeamViewer_Service.exe → services.exe
- **Zscaler ZDP** — DLP agent deployed/deploying fleet-wide. Thread injection and sensor handle access are expected behavior. Expected parent: services.exe
- **Rapid7 Insight Agent** — Vulnerability scanner. PowerShell, registry saves, network discovery are expected. Expected parent: ir_agent.exe
- **GlobalProtect** — VPN client. Route commands and network checks expected.
- **OneDrive** — File sync. Can trigger ProcRansomware FPs during heavy sync operations.
- **Docker Desktop** — Developer tool. PowerShell, process enumeration expected on dev workstations.

## Known Host Types

- **MCSIMULATOR##** — MasterCard Authorization Simulator (MAS) test servers. FIS.OTS.Mastercard.Launcher.exe + SQL Server LocalDB is expected.
- **EP##-PRD/STG/DEV** — Payment processing servers. WinSCP, ClearingOptimizer, batch jobs are expected but verify user/timing.
- **ATL-[username]#** — Employee workstations (Lenovo ThinkPads, Windows 11 Enterprise, AzureAD joined).
- **VTAPP##-DEV/TST / VTAPP##STG** — Virtual Terminal (VT) payment-app servers (AWS EC2, Windows Server 2022, IIS `VTApp` app pool, OU `...\VT Servers\AWS\Servers`). Dev/test/stage tiers. Developer activity over RDP, ASP.NET runtime compilation (w3wp.exe writing to Temporary ASP.NET Files), nuget restore, and connections to the dev Aurora Postgres RDS + AWS IMDS (169.254.169.254) are expected. Verify user/timing.

## Known In-House Tools (verify process tree + network each time)

- **AST.exe (`C:\VTBGTask\...\AST\AST.exe`)** — In-house VT "background task" console app under active development by the VT dev team (owner: ikramul.c, a contract engineer in Thailand / +66, UTC+7). Runs **scheduled via svchost.exe on VTAPP02-DEV** and **interactively via explorer.exe on dev boxes** (e.g. VTAPP01-DEV) during development/testing. Because it is under active development, its SHA256 changes frequently, so **low/unique global prevalence is EXPECTED and is not itself suspicious**. Triggers `DropAndExecRDPFile` / `CLIDropAndExecRDPFile` when run over RDP. Legitimate network: dev Aurora Postgres RDS (10.184.30.41:5432), internal corporate HTTPS, AWS IMDS. Reference: **SEC-3718** (confirmed benign). Hygiene note: it has been run from ad-hoc personal paths (e.g. `C:\VTBGTask\Ikram Space\...`); flag relocation to a managed, code-signed path but do not treat the messy path alone as malicious.
- **studio-agent (`/Users/cbutkus/aicode/cb/bambu-monitor/studio-agent/studio-agent`)** — In-house **Bambu Lab 3D-printer monitoring** tool written in Go, developed by **cbutkus (Charles Butkus)** on his Mac workstation **Mac.kurast.io** (macOS, Apple Silicon; formerly named `ip-172-19-8-2.ec2.internal`). Compiled and run from the **Cursor IDE integrated terminal** via `go build -o studio-agent . && ./studio-agent`; the parent zsh sets `BBL_CONFIG=$HOME/Library/Application Support/BambuStudio` and `BBL_PRINTER=...` and manages a local MQTT listener (TCP:8766) and a localhost API (127.0.0.1:8765). Because it is recompiled on every build and is **unsigned Go**, its SHA256 changes each run and **low global / unique local prevalence is EXPECTED** — it trips lowest/low-confidence ML detections (`MLSensor-Low`, `LowConfidenceMalware`, `LowestConfidenceMalware`) and the Mac Desktop prevention policy may block/quarantine it. Legitimate network: local DNS resolver (172.20.0.x:53), Bambu Lab cloud API `api.bambulab.com` (Cloudflare-fronted, e.g. 172.64.x.x:443), and loopback. Reference: **SEC-3723** (confirmed benign); related **SEC-3365** (same user/host, prior dev-tool ML FP). Hygiene note: unsigned dev builds under `~/aicode` will keep tripping ML — prefer code-signing over a standing exclusion; if released from quarantine for the developer, do NOT create a blanket exclusion. Still re-verify the process tree (Cursor → zsh → go build → ./studio-agent) and network each time — a known-good filename/path can be reused.

## Common False Positive Patterns (still verify — don't auto-close)

- UmppcBypassSuspected from SQL Server, VirtualBox, or other performance-optimized software
- SuspiciousRMMUsage from TeamViewer (authorized)
- RemotePivotInjection / SensorHandleOpenedLow from Zscaler ZDP
- ProcRansomware from OneDrive file sync
- DoubleExtensionWritten from Lenovo Vantage updates
- SAMHashDump.Untrusted from Dell SupportAssist Remediation
- PowershellExecution from Rapid7 Insight Agent vulnerability scans

## Best Practices

- Treat every entry as an effort-saver, not an auto-clear rule.
- Always re-verify the process tree and network activity even for a known tool.
- Record the confirming SEC ticket when you add or update an entry.
- Prefer code-signing or relocation fixes over standing exclusions for noisy in-house tools.
