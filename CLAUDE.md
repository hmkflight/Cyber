# Moatline: rules for building this repo

Moatline is a security company for AI-agent ecosystems. This repo starts with the free **Agent Inventory Scan**: a command-line tool that finds every agent configuration, MCP server, hook, plugin and skill on a machine and reports the risks in plain language.

"Moatline" is a working name. It may change.

## Hard rules (never break these)

1. **The scanner is read-only.** It never writes, moves or deletes files outside its own output. Open every file for reading only.
2. **No network calls.** The scanner never imports or uses `socket`, `urllib.request`, `http.client`, `requests` or any network library. `tests/test_safety.py` enforces this.
3. **Never print or store a secret.** Environment variable values and header values are never shown; only their names are. Anything that looks like a token in a command, argument or URL is replaced with `[REDACTED]` by `moatline.redact`. Show at most the last 4 characters of a secret, and only in findings that need them.
4. **Standard library only** at runtime. Python 3.11+. Dev tools (pytest) are fine in `[project.optional-dependencies]`.
5. **Never crash on bad input.** A missing, unreadable, oversized or malformed file becomes an `error` entry in the report, not an exception.
6. **Every feature ships with tests.** Use fake configs built in `tmp_path`. Never read the real home folder in tests. Fake secrets must look fake (for example `sk-test-FAKE...`).

## How to work in this repo

- Plan first. Describe the change and wait for approval before writing code on anything bigger than a small fix.
- One feature per branch and pull request. Run `python -m pytest -q` before saying a task is done.
- Keep functions small and typed. Prefer `pathlib.Path` and `dataclasses`.
- Explain each change in plain English in the pull request. Include how it could fail and how an attacker might abuse it.
- Add a one-line entry to `DECISIONS.md` for any choice that future sessions need to know about.
- When a finding is added (week 4 onward), map it to the OWASP Top 10 for Agentic Applications and write a one-sentence, non-technical explanation of why it matters.

## Layout

- `src/moatline/cli.py`: command-line entry point (`moatline scan`)
- `src/moatline/models.py`: data types for discovered assets and errors
- `src/moatline/redact.py`: secret masking. Every string from a config file passes through it before output
- `src/moatline/discovery/`: one module per AI tool (`claude_code.py` first; Copilot, Codex, Gemini CLI and Cursor next)
- `src/moatline/report.py`: text and JSON output
- `tests/`: pytest tests with fake home and project folders

## Where the plans live

The company plans (service list, cross-platform plan, 90-day plan) are in Hudson's "Cyber security" Claude project. This repo follows the 90-day plan: weeks 1–2 build the scanner skeleton and Claude Code discovery.
