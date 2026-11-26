"""Discover Gemini CLI configuration.

Locations (geminicli.com docs, Nov 2026):
- Settings: ~/.gemini/settings.json (user), .gemini/settings.json (project),
  system settings and system defaults:
    Linux   /etc/gemini-cli/settings.json and system-defaults.json
    macOS   /Library/Application Support/GeminiCli/...
    Windows C:\\ProgramData\\gemini-cli\\...
  GEMINI_CLI_SYSTEM_SETTINGS_PATH and GEMINI_CLI_SYSTEM_DEFAULTS_PATH override.
- MCP servers: "mcpServers" in settings and in each extension's
  gemini-extension.json (~/.gemini/extensions/<name>/).
- Hooks: "hooks" in settings, and hooks/hooks.json inside an extension.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from moatline.discovery.base import ScanContext, list_children, read_json, system_dir
from moatline.discovery.common import as_scalar, dig, scan_hooks_block, scan_mcp_block, settings_asset
from moatline.models import Asset, ScanResult

PLATFORM = "gemini_cli"

_SYSTEM_DIRS = {
    "darwin": Path("/Library/Application Support/GeminiCli"),
    "linux": Path("/etc/gemini-cli"),
    "win32": Path("C:/ProgramData/gemini-cli"),
}

# (label, path into settings.json) for security-relevant settings.
_SECURITY_SETTINGS = (
    ("default_approval_mode", ("general", "defaultApprovalMode")),
    ("sandbox", ("tools", "sandbox")),
    ("disable_yolo_mode", ("security", "disableYoloMode")),
    ("secure_mode", ("admin", "secureModeEnabled")),
    ("folder_trust", ("security", "folderTrust", "enabled")),
    ("env_var_redaction", ("security", "environmentVariableRedaction", "enabled")),
)
_LIST_SETTINGS = (
    ("auto_allowed_tools", ("tools", "allowed")),
    ("mcp_allowed", ("mcp", "allowed")),
    ("mcp_excluded", ("mcp", "excluded")),
)


def _settings(path: Path, scope: str, result: ScanResult) -> None:
    data = read_json(path, PLATFORM, result, allow_comments=True)
    if not isinstance(data, dict):
        return
    server_count = scan_mcp_block(data.get("mcpServers"), PLATFORM, scope, path, result)
    hook_count = scan_hooks_block(data.get("hooks"), PLATFORM, scope, path, result)
    details: dict[str, Any] = {"mcp_server_count": server_count, "hook_count": hook_count}
    for label, keys in _SECURITY_SETTINGS:
        value = as_scalar(dig(data, *keys))
        if value is not None:
            details[label] = value
    for label, keys in _LIST_SETTINGS:
        value = dig(data, *keys)
        if isinstance(value, list):
            details[label] = len(value)
    # Older flat settings files used top-level keys.
    if "sandbox" not in details and as_scalar(data.get("sandbox")) is not None:
        details["sandbox"] = as_scalar(data["sandbox"])
    if as_scalar(data.get("autoAccept")) is not None:
        details["auto_accept"] = as_scalar(data["autoAccept"])
    settings_asset(PLATFORM, scope, path, details, result)


def _extensions(folder: Path, scope: str, result: ScanResult) -> None:
    for ext_dir in list_children(folder, PLATFORM, result):
        manifest = ext_dir / "gemini-extension.json"
        if not (ext_dir.is_dir() and manifest.is_file()):
            continue
        data = read_json(manifest, PLATFORM, result, allow_comments=True)
        if not isinstance(data, dict):
            continue
        server_count = scan_mcp_block(
            data.get("mcpServers"), PLATFORM, "extension", manifest, result, extra={"extension": ext_dir.name}
        )
        hooks_file = ext_dir / "hooks" / "hooks.json"
        hooks = read_json(hooks_file, PLATFORM, result, allow_comments=True)
        hook_count = scan_hooks_block(hooks.get("hooks") if isinstance(hooks, dict) else None, PLATFORM, "extension", hooks_file, result)
        details: dict[str, Any] = {
            "version": as_scalar(data.get("version")),
            "mcp_server_count": server_count,
            "hook_count": hook_count,
            "excluded_tools": len(data["excludeTools"]) if isinstance(data.get("excludeTools"), list) else 0,
            "has_env_file": (ext_dir / ".env").is_file(),
        }
        result.assets.append(Asset("extension", PLATFORM, scope, str(data.get("name") or ext_dir.name), str(manifest), details))


def scan(ctx: ScanContext) -> ScanResult:
    result = ScanResult()
    system = system_dir(ctx, "gemini_system", _SYSTEM_DIRS)

    defaults_override = ctx.env.get("GEMINI_CLI_SYSTEM_DEFAULTS_PATH")
    settings_override = ctx.env.get("GEMINI_CLI_SYSTEM_SETTINGS_PATH")
    if defaults_override:
        _settings(Path(defaults_override), "managed", result)
    elif system is not None:
        _settings(system / "system-defaults.json", "managed", result)
    if settings_override:
        _settings(Path(settings_override), "managed", result)
    elif system is not None:
        _settings(system / "settings.json", "managed", result)

    gemini_home = ctx.home / ".gemini"
    _settings(gemini_home / "settings.json", "user", result)
    _settings(ctx.project / ".gemini" / "settings.json", "project", result)

    _extensions(gemini_home / "extensions", "user", result)
    _extensions(ctx.project / ".gemini" / "extensions", "project", result)
    return result
