"""Discover OpenAI Codex configuration.

Locations (OpenAI docs, Nov 2026):
- Config: $CODEX_HOME/config.toml (default ~/.codex/config.toml) and the
  project's .codex/config.toml (trusted projects only).
- MCP servers: [mcp_servers.<name>] tables in config.toml. Keys include
  command, args, env, env_vars, cwd, url, bearer_token_env_var, http_headers,
  env_http_headers, enabled, enabled_tools.
- Hooks: ~/.codex/hooks.json, [hooks] in ~/.codex/config.toml, and the same
  two files under the project's .codex folder.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from moatline.discovery.base import ScanContext, read_json, read_toml
from moatline.discovery.common import as_scalar, dig, scan_hooks_block, scan_mcp_block, settings_asset
from moatline.models import ScanResult

PLATFORM = "codex"

# Settings that change how much Codex can do without asking.
_SETTING_KEYS = ("approval_policy", "sandbox_mode", "model", "allow_managed_hooks_only")


def _codex_home(ctx: ScanContext) -> Path:
    override = ctx.env.get("CODEX_HOME")
    return Path(override).expanduser() if override else ctx.home / ".codex"


def _config(path: Path, scope: str, result: ScanResult) -> None:
    data = read_toml(path, PLATFORM, result)
    if data is None:
        return
    server_count = scan_mcp_block(data.get("mcp_servers"), PLATFORM, scope, path, result)
    hook_count = scan_hooks_block(data.get("hooks"), PLATFORM, scope, path, result)
    details: dict[str, Any] = {"mcp_server_count": server_count, "hook_count": hook_count}
    for key in _SETTING_KEYS:
        value = as_scalar(data.get(key))
        if value is not None:
            details[key] = value
    network = as_scalar(dig(data, "sandbox_workspace_write", "network_access"))
    if network is not None:
        details["sandbox_network_access"] = network
    profiles = data.get("profiles")
    if isinstance(profiles, dict) and profiles:
        details["profiles"] = sorted(str(p) for p in profiles)
    settings_asset(PLATFORM, scope, path, details, result)


def _hooks_json(path: Path, scope: str, result: ScanResult) -> None:
    data = read_json(path, PLATFORM, result, allow_comments=True)
    if isinstance(data, dict):
        scan_hooks_block(data.get("hooks"), PLATFORM, scope, path, result)


def scan(ctx: ScanContext) -> ScanResult:
    result = ScanResult()
    home = _codex_home(ctx)
    _config(home / "config.toml", "user", result)
    _hooks_json(home / "hooks.json", "user", result)
    project = ctx.project / ".codex"
    _config(project / "config.toml", "project", result)
    _hooks_json(project / "hooks.json", "project", result)
    return result
