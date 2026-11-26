# Decisions

One line per decision, newest at the bottom. Format: date: decision (why).

- 2026-11-25: Name is "Moatline" (confirmed by Hudson; free on PyPI).
- 2026-11-25: Python 3.11+, standard library only at runtime (easy install, small attack surface, `tomllib` built in for Codex's TOML configs).
- 2026-11-25: The scanner is read-only and makes no network calls (clients can run it without trusting us with anything).
- 2026-11-25: Secrets are never printed; env and header values are dropped, token-like strings are redacted (a security tool must not leak what it finds).
- 2026-11-25: Start with Claude Code discovery, then Copilot, Codex, Gemini CLI and Cursor (follows the 90-day plan).
- 2026-11-25: License is Apache-2.0 for the free scanner (confirmed by Hudson; permissive, includes a patent grant, common for open-core security tools).
- 2026-11-25: Text reports shorten home paths inside every detail, not only whole values (Hudson's first real scan showed /Users/<name> in project paths).
