# Decisions

One line per decision, newest at the bottom. Format: date: decision (why).

- 2026-11-25: Name is "Moatline" (confirmed by Hudson; free on PyPI).
- 2026-11-25: Python 3.11+, standard library only at runtime (easy install, small attack surface, `tomllib` built in for Codex's TOML configs).
- 2026-11-25: The scanner is read-only and makes no network calls (clients can run it without trusting us with anything).
- 2026-11-25: Secrets are never printed; env and header values are dropped, token-like strings are redacted (a security tool must not leak what it finds).
- 2026-11-25: Start with Claude Code discovery, then Copilot, Codex, Gemini CLI and Cursor (follows the 90-day plan).
- 2026-11-25: License is Apache-2.0 for the free scanner (confirmed by Hudson; permissive, includes a patent grant, common for open-core security tools).
- 2026-11-25: Text reports shorten home paths inside every detail, not only whole values (Hudson's first real scan showed /Users/<name> in project paths).
- 2026-11-25: Week 3 adds GitHub Copilot, VS Code, OpenAI Codex, Gemini CLI and Cursor, using shared parsers so each tool's module only lists file locations.
- 2026-11-25: Non-Claude config files are read as "JSON with comments" (VS Code and others allow comments and trailing commas). Claude Code files stay strict, because Claude Code ignores broken files.
- 2026-11-25: The project-root .mcp.json is listed once, under Claude Code, marked "also used by GitHub Copilot", to avoid double counting.
- 2026-11-25: Not covered yet: skills and agents for non-Claude tools, Codex admin-managed config, Cursor's Windows enterprise path, Add when their file locations are confirmed.
- 2026-11-25: Antigravity is not supported (Hudson's decision). Don't add it unless he asks.
- 2026-11-25: Week 4 risk checks live in `checks.py` and only read assets discovery already redacted, so a check can never reveal a secret. Each finding has an ID (ML001-ML010), severity, plain "why" and "fix", and an OWASP Agentic (ASI) mapping.
- 2026-11-25: A secret counts as "typed into a file" when the value is not a `${VAR}`-style reference and its name or shape looks secret. Switches, small numbers, paths and plain URLs are ignored to keep false alarms down.
- 2026-11-25: Only Anthropic's reserved marketplace names count as official plugins. Community marketplaces are flagged (low), because their plugins are written by third parties.
- 2026-11-25: An MCP package is "pinned" only with an exact version (npm `x.y.z`, Python `==` or `@version`, Docker tag or digest). Ranges like `^1.2` still update on their own.
- 2026-11-25: The home folder is replaced with `~` anywhere it appears in a report, including inside hook commands.
- 2026-11-25: "Shared credentials" (ML010) compares key names only, never values: the same secret-looking variable or header name used by MCP servers in two or more AI tools.
- 2026-11-25: The text report shows control and invisible characters as \x{..} codes, so a hostile config (for example a cloned repo's .mcp.json) can't use terminal escape codes to hide findings or fake a clean report.
- 2026-11-25: Claude Code's sandbox counts as "on" only when user or managed settings turn it on; a project's own settings cover just that project.
- 2026-11-26: "Weeks" in the 90-day plan are milestones, not calendar weeks. Build pace is set by Hudson's testing, so milestones can be finished faster than one per week.
- 2026-11-26: The last 4 characters of a secret appear only in the ML004 finding, and only for values of 20+ characters. They live in `Asset.secret_endings`, which is never part of the inventory output.
- 2026-11-26: Findings of the same kind are grouped in text and Markdown (one entry, every place listed). JSON and SARIF keep one entry per finding for machines.
- 2026-11-26: Within a severity, findings are ordered by what to fix first: exposed keys (ML004, ML005), powerful tools in reach (ML006), agents acting alone (ML002, ML003), then the rest.
- 2026-11-26: Markdown reports escape everything from config files and show names and paths as code, so a hostile name can't add links, images or HTML to a report.
- 2026-11-26: `--output` only creates new files (Python's "x" mode) and never overwrites, so the scanner stays read-only for everything except its own report.
- 2026-11-26: SARIF uses repo-relative paths for project files and `~/...` for others. Each rule's GitHub "security-severity" is the worst level that check can report; each result's level is its own severity. The SARIF file isn't checked against the official schema yet (no network in tests); tests check its required structure instead.
