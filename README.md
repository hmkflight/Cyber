# Moatline: Agent Inventory Scan

Moatline finds every AI-agent configuration on a machine and lists what each agent can reach: MCP servers, hooks, plugins, skills, subagents, custom commands and settings. It is the free first step of the Moatline catalog.

## What it covers today (v0.1.0)

| AI tool | What the scan reads |
|---|---|
| Claude Code | Settings (managed, user, project, local), MCP servers (user, local, project, managed), hooks, plugins, marketplaces, skills, subagents, commands |
| GitHub Copilot | `~/.copilot/mcp-config.json`, Copilot hooks (user, repo `.github/hooks`, admin policy hooks), `.github/copilot` settings |
| VS Code | User-profile and workspace `mcp.json` (Stable and Insiders) |
| OpenAI Codex | `~/.codex/config.toml` and project `.codex/config.toml` (MCP servers, approval and sandbox settings, hooks), `hooks.json` |
| Gemini CLI | System, user and project `settings.json` (MCP servers, approval and trust settings, hooks), extensions |
| Cursor | User and project `mcp.json`, user, project and enterprise `hooks.json` |

Antigravity is not supported (decision, November 2026).

## Findings

After the inventory, the report lists risky settings, most serious first. Each finding says where it is, why it matters in plain words, how to fix it, and which [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/) risk it belongs to.

| ID | What it looks for | Severity | OWASP |
|---|---|---|---|
| ML001 | MCP server that downloads its newest version on every start (`@latest`, no version, Docker `:latest`) | Medium | ASI04 Supply chain |
| ML002 | Agent set to act without asking (Claude `bypassPermissions` or a bare `Bash` allow rule, Codex `approval_policy = "never"`, Gemini `auto_edit`/`yolo`, trusted servers) | High to low | ASI02 Tool misuse |
| ML003 | No sandbox (Codex `danger-full-access`, Claude sandbox off, Gemini folder trust off) | High to low | ASI05 Code execution |
| ML004 | Secret typed straight into a config file or URL | High | ASI03 Identity and privilege |
| ML005 | Secret written into a command line | High | ASI03 Identity and privilege |
| ML006 | MCP server switched on for the whole home folder, or a money, messaging or data tool on everywhere | High to low | ASI03 Identity and privilege |
| ML007 | Hook defined inside a project folder (runs whatever the project author wrote) | Medium | ASI05 Code execution |
| ML008 | Remote server or hook over plain `http://` | Medium | ASI07 Agent communication |
| ML009 | Plugin or extension from a third-party marketplace | Low | ASI04 Supply chain |
| ML010 | The same key (for example `GITHUB_TOKEN`) given to MCP servers in two or more AI tools | Low | ASI03 Identity and privilege |

Findings show names, never secret values.

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
moatline scan --fail-on high       # exit code 1 if anything high is found (for CI)
```

## Develop

```bash
python -m pytest -q
```

Read `CLAUDE.md` before changing code. It holds the rules every change must follow. Record important choices in `DECISIONS.md`.
