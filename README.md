# CrowdStrike Detection Investigation (Kiro Power)

A Kiro Power for structured investigation of CrowdStrike Falcon detections (Automated Leads and endpoint detections). It walks a mandatory 8-step decision tree, produces a five-verdict determination with a confidence level and contact routing, and generates a structured investigation report.

**Read-only against Falcon by policy.** The power never modifies Falcon state. Closing or updating detections remains a manual analyst action in the Falcon console.

- **Version:** 1.0.0
- **License:** MIT
- **Author:** Homam Zituni
- **Scope:** Falcon-only (no Jira/Confluence integration)

## Contents

| File | Purpose |
|------|---------|
| `plugin.json` | Power manifest (name, version, description, keywords, license). |
| `mcp.json` | MCP server definition for Falcon. |
| `skills/investigate-detection/SKILL.md` | The investigation workflow (8-step decision tree, verdicts, report generation). |
| `skills/known-environment/SKILL.md` | Known-benign environment context used to shortcut recognized patterns. |

> Adjust the skill paths above to match your repo layout.

## Skills

### investigate-detection
The main workflow. Takes a Falcon detection, hostname, or timestamp, works through the decision tree, and outputs a verdict, confidence, contact routing, and a structured investigation report.

### known-environment
A reference of authorized software, known host types, in-house tools, and common false-positive patterns. It is consulted during Steps 1, 5, 6, and 7 of an investigation.

Important rules:
- Entries are **verification aids, not clearances**. Always re-verify the process tree and network activity, even for a known tool.
- Add or update an entry only after benign behavior is **confirmed** by evidence or owner confirmation, and record the confirming source (for example, the investigation report or the owner's confirmation).
- Prefer code-signing or relocation fixes over standing exclusions for noisy in-house tools.
- Updating this file is allowed without approval. Modifying Falcon alerts is prohibited.

## Investigation Workflow

1. **Trigger:** the analyst provides a hostname and/or timestamp, or a detection ID.
2. **Discovery:** the agent pulls host details and all detections in the timeframe via the Falcon MCP.
3. **Analysis:** a mandatory 8-step decision tree runs per detection:
   1. Host Context
   2. Detection Metadata
   3. Process Tree
   4. Network Verification
   5. File & Prevalence
   6. Historical Correlation
   7. Documentation & Auth Check
   8. Vulnerability & Hygiene
4. **Documentation check:** correlates findings against known-environment context and any user-supplied anchors (authorized software, host naming conventions).
5. **Verdict:** one of five, with confidence and resolution routing (contact matrix):
   - False Positive
   - False Positive with Finding
   - Requires Confirmation
   - Suspicious / Escalate
   - True Positive / IR
6. **Deliverable:** a structured investigation report.

### Scope
Automated Leads and endpoint detections across Falcon products (EPP, IDP, XDR, OverWatch). Detection types covered: Defense Evasion, Process Injection, Credential Access, Command & Control, Execution, Impact, Lateral Movement.

## MCP Server

Configured in `mcp.json`, launched via `uvx` over stdio:

| Server | Package | Used for |
|--------|---------|----------|
| `falcon` | `falcon-mcp` | Falcon data. Enabled modules: `hosts`, `detections`, `ioc`, `ngsiem`. |

> The original design notes also list `intel` as a module. Confirm whether it is enabled in `mcp.json` and update this table to match.

## Setup

1. Install [`uv`](https://docs.astral.sh/uv/) so `uvx` is available on your PATH.
2. Set the following environment variables in the session you run from. Never commit values to the repo or embed them in the power.
   - `FALCON_CLIENT_ID`
   - `FALCON_CLIENT_SECRET`
   - `FALCON_BASE_URL`
3. Use a Falcon API client with **read-only** scopes only, for the modules listed above.
4. Open the Kiro IDE, go to the **Powers** section, and upload the power folder. That is the entire install step.
5. Confirm the Falcon MCP shows as connected.

> Verify the `falcon-mcp` package name, supported modules, and required API scopes against its current documentation before rollout.

> If the power is already loaded in a running Kiro session, it may hold an older version in memory. Reload the power or start a fresh session so the current files are used.

## Usage

Invocation is intent-based: the keywords below are routing hints, not a literal string match. Start your message with **investigate** or **triage** and include a hostname, timestamp, or detection ID for the most reliable routing.

| Request | Example |
|---------|---------|
| Hostname + timestamp | `investigate <HOSTNAME> at <TIMESTAMP>` |
| Hostname only | `investigate <HOSTNAME>` |
| Detection ID | `investigate <composite_id>` |
| Bulk request | `investigate all new detections on <HOSTNAME>` |
| Fleet check | `check if <detection> is firing across other hosts` |

A bare hostname with no verb is ambiguous and may not route on its own.

**Power-level keywords** (associate a request with this power, from `plugin.json`): `crowdstrike`, `falcon`, `detection-investigation`, `endpoint-detection`, `automated-leads`, `soc-triage`, `incident-response`.

## Security Notes

- Credentials are supplied through environment variables only.
- Rotate any credential that is accidentally shared or committed, and report it to IT/Security.
- Treat host names, user names, and IPs in the known-environment file and in generated reports as sensitive internal data.

## Contributing

Update `known-environment` whenever an investigation confirms a new benign tool, host type, or pattern. Record the confirming source (investigation report or owner confirmation).

## Open Questions

- Should this power stay separate from the Falcon Threat-Hunting and InfoSec IR powers, or cross-reference them?
- Should known-environment context (authorized software, host naming) live in shared steering so it stays current across installs?
