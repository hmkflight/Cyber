# Moatline: Agent Inventory Scan

Moatline finds every AI-agent configuration on a machine and lists what each agent can reach: MCP servers, hooks, plugins, skills, subagents, custom commands and settings. It is the free first step of the Moatline catalog.

## What it covers today (v0.0.2)

| AI tool | What the scan reads |
|---|---|
| Claude Code | Settings (managed, user, project, local), MCP servers (user, local, project, managed), hooks, plugins, marketplaces, skills, subagents, commands |
| GitHub Copilot | `~/.copilot/mcp-config.json`, Copilot hooks (user, repo `.github/hooks`, admin policy hooks), `.github/copilot` settings |
| VS Code | User-profile and workspace `mcp.json` (Stable and Insiders) |
| OpenAI Codex | `~/.codex/config.toml` and project `.codex/config.toml` (MCP servers, approval and sandbox settings, hooks), `hooks.json` |
| Gemini CLI | System, user and project `settings.json` (MCP servers, approval and trust settings, hooks), extensions |
| Cursor | User and project `mcp.json`, user, project and enterprise `hooks.json` |

Risk checks and plain-language findings come in week 4.

## Safety promises

- **Read-only.** It never changes a file.
- **No network.** It never connects to anything. The tests block network access and fail if the scanner tries.
- **No secrets in reports.**
  - Values of environment variables and headers are never shown, only their names.
  - Token-like strings in commands and URLs are replaced with `[REDACTED]`.
  - Your home folder is shown as `~`.

## Install (from source, for now)

Requires Python 3.11 or newer.

```bash
git clone <repo-url> moatline
cd moatline
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Use

```bash
moatline scan                      # scan your machine and the current project folder
moatline scan --project ~/code/app # scan a different project folder
moatline scan --format json        # machine-readable output
```

## Develop

```bash
python -m pytest -q
```

Read `CLAUDE.md` before changing code. It holds the rules every change must follow. Record important choices in `DECISIONS.md`.
