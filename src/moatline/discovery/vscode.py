"""Discover VS Code MCP configuration (used by Copilot Chat in VS Code).

Locations (VS Code docs, Nov 2026):
- Workspace: .vscode/mcp.json, top-level "servers" (comments allowed).
- User profile mcp.json:
  macOS   ~/Library/Application Support/Code/User/mcp.json
  Linux   ~/.config/Code/User/mcp.json
  Windows %APPDATA%\\Code\\User\\mcp.json
  The same paths under "Code - Insiders" for the Insiders build.
"""

from __future__ import annotations

import json
from pathlib import Path

from moatline.discovery.base import ScanContext, read_json
from moatline.discovery.common import scan_mcp_block
from moatline.models import ScanResult
from moatline.redact import redact_text

PLATFORM = "vscode"
_EDITIONS = ("Code", "Code - Insiders")


def _user_dirs(ctx: ScanContext) -> list[Path]:
    if ctx.platform_os == "darwin":
        base = ctx.home / "Library" / "Application Support"
    elif ctx.platform_os == "win32":
        appdata = ctx.env.get("APPDATA")
        base = Path(appdata) if appdata else ctx.home / "AppData" / "Roaming"
    else:
        base = ctx.home / ".config"
    return [base / edition / "User" for edition in _EDITIONS]


def _mcp_file(path: Path, scope: str, result: ScanResult, edition: str | None = None) -> None:
    data = read_json(path, PLATFORM, result, allow_comments=True)
    if not isinstance(data, dict):
        return
    inputs = data.get("inputs") if isinstance(data.get("inputs"), list) else []
    input_ids = [str(i["id"]) for i in inputs if isinstance(i, dict) and i.get("id")]
    # VS Code uses "servers"; accept "mcpServers" too in case of copied configs.
    block = data.get("servers") if isinstance(data.get("servers"), dict) else data.get("mcpServers")
    if not isinstance(block, dict):
        return
    for name, server in block.items():
        extra: dict[str, object] = {}
        # Inputs are values VS Code asks the user for; list only the ones this server uses.
        used = sorted(redact_text(i) for i in input_ids if f"${{input:{i}}}" in json.dumps(server))
        if used:
            extra["input_names"] = used
        if edition and edition != "Code":
            extra["edition"] = edition
        scan_mcp_block({name: server}, PLATFORM, scope, path, result, extra=extra or None)


def scan(ctx: ScanContext) -> ScanResult:
    result = ScanResult()
    for user_dir in _user_dirs(ctx):
        _mcp_file(user_dir / "mcp.json", "user", result, edition=user_dir.parent.name)
    _mcp_file(ctx.project / ".vscode" / "mcp.json", "project", result)
    return result
