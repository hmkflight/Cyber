"""Discover Cursor configuration.

Locations (Cursor docs and forum, Nov 2026):
- MCP servers: ~/.cursor/mcp.json and the project's .cursor/mcp.json ("mcpServers").
- Hooks: ~/.cursor/hooks.json and the project's .cursor/hooks.json
  ({"version": 1, "hooks": {"beforeShellExecution": [{"command": ...}]}}).
- Enterprise hooks: /Library/Application Support/Cursor/hooks.json (macOS),
  /etc/cursor/hooks.json (Linux).
"""

from __future__ import annotations

from pathlib import Path

from moatline.discovery.base import ScanContext, read_json, system_dir
from moatline.discovery.common import scan_hooks_block, scan_mcp_block
from moatline.models import ScanResult

PLATFORM = "cursor"

_ENTERPRISE_DIRS = {
    "darwin": Path("/Library/Application Support/Cursor"),
    "linux": Path("/etc/cursor"),
}


def _mcp(path: Path, scope: str, result: ScanResult) -> None:
    data = read_json(path, PLATFORM, result, allow_comments=True)
    if isinstance(data, dict):
        scan_mcp_block(data.get("mcpServers"), PLATFORM, scope, path, result)


def _hooks(path: Path, scope: str, result: ScanResult) -> None:
    data = read_json(path, PLATFORM, result, allow_comments=True)
    if isinstance(data, dict):
        scan_hooks_block(data.get("hooks"), PLATFORM, scope, path, result)


def scan(ctx: ScanContext) -> ScanResult:
    result = ScanResult()
    user = ctx.home / ".cursor"
    project = ctx.project / ".cursor"
    _mcp(user / "mcp.json", "user", result)
    _mcp(project / "mcp.json", "project", result)
    _hooks(user / "hooks.json", "user", result)
    _hooks(project / "hooks.json", "project", result)
    enterprise = system_dir(ctx, "cursor_enterprise", _ENTERPRISE_DIRS)
    if enterprise is not None:
        _hooks(enterprise / "hooks.json", "managed", result)
    return result
