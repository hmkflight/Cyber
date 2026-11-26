# Moatline: Agent Inventory Scan

Moatline finds every AI-agent configuration on a machine and lists what each agent can reach: MCP servers, hooks, plugins, skills, subagents, custom commands and settings. It is the free first step of the Moatline catalog.

## What it covers today (v0.0.1)

| AI tool | Status |
|---|---|
| Claude Code | Settings (managed, user, project, local), MCP servers (user, local, project, managed), hooks, plugins, marketplaces, skills, subagents, commands |
| GitHub Copilot, OpenAI Codex, Gemini CLI, Cursor | Planned (week 3) |

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
