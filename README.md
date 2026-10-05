# CrowdStrike Detection Investigation

A plugin for structured investigation of CrowdStrike Falcon detections (Automated Leads and endpoint detections). It walks a mandatory 8-step decision tree, produces a five-verdict determination with a confidence level and contact routing, and drafts a SEC Jira ticket.

**Read-only against Falcon by policy.** The plugin never modifies Falcon alerts.

- **Version:** 1.0.0
- **License:** MIT
- **Author:** Homam Zituni

## Contents

| File | Purpose |
|------|---------|
| `plugin.json` | Plugin manifest (name, version, description, keywords, license). |
| `mcp.json` | MCP server definitions for Falcon and Atlassian (Jira/Confluence). |
| `skills/investigate-detection/SKILL.md` | The investigation workflow (8-step decision tree, verdicts, ticket drafting). |
| `skills/known-environment/SKILL.md` | Known-benign environment context used to shortcut recognized patterns. |

> Adjust the skill paths above to match your repo layout.

## Skills

### investigate-detection
The main workflow. Takes a Falcon detection, works through the decision tree, and outputs a verdict, confidence, and who to contact. Can draft a SEC Jira ticket.

### known-environment
A reference of authorized software, known host types, in-house tools, and common false-positive patterns. It is consulted during Steps 1, 5, 6, and 7 of an investigation.

Important rules:
- Entries are **verification aids, not clearances**. Always re-verify the process tree and network activity, even for a known tool.
- Add or update an entry only after benign behavior is **confirmed** by evidence or owner confirmation, and include the confirming SEC ticket.
- Prefer code-signing or relocation fixes over standing exclusions for noisy in-house tools.
- Updating this file is allowed without approval. Creating Jira tickets requires an explicit user instruction. Modifying Falcon alerts is prohibited.

## MCP Servers

Configured in `mcp.json`, both launched via `uvx` over stdio:

| Server | Package | Used for |
|--------|---------|----------|
| `falcon` | `falcon-mcp` | Falcon data. Enabled modules: `hosts`, `detections`, `ioc`, `ngsiem`. |
| `atlassian` | `mcp-atlassian` | Jira and Confluence (SEC ticket drafting and lookup). |

## Setup

1. Install [`uv`](https://docs.astral.sh/uv/) so `uvx` is available on your PATH.
2. Set the following environment variables. Never commit values to the repo.

   **Falcon**
   - `FALCON_CLIENT_ID`
   - `FALCON_CLIENT_SECRET`
   - `FALCON_BASE_URL`

   **Atlassian**
   - `JIRA_URL`, `JIRA_USERNAME`, `JIRA_API_TOKEN`
   - `CONFLUENCE_URL`, `CONFLUENCE_USERNAME`, `CONFLUENCE_API_TOKEN`

3. Use a Falcon API client with **read-only** scopes only, for the modules listed above.
4. Install the plugin in your agent environment and confirm both MCP servers connect.

> Verify the `falcon-mcp` and `mcp-atlassian` package names, supported modules, and required API scopes against their current documentation before rollout.

## Usage

Ask the agent to investigate a detection, for example:

> Investigate this Falcon detection: `<detection ID or Automated Lead link>`

The agent will follow the decision tree, check the known-environment context, and return a verdict with confidence and contact routing. Ask it explicitly if you want a SEC Jira ticket drafted or created.

## Security Notes

- Credentials are supplied through environment variables only.
- Rotate any credential that is accidentally shared or committed, and report it to IT/Security.
- Treat host names, user names, and IPs in the known-environment file as sensitive internal data.

## Contributing

Update `known-environment` whenever an investigation confirms a new benign tool, host type, or pattern. Include the SEC ticket reference.
