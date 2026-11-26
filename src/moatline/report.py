"""Turn a ScanResult into text or JSON.

Paths under the user's home folder are shown as ``~/...`` so a shared report
doesn't reveal the username.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from moatline import __version__
from moatline.discovery.base import ScanContext
from moatline.models import Asset, ScanResult

KIND_TITLES = {
    "mcp_server": "MCP servers",
    "hook": "Hooks",
    "plugin": "Plugins",
    "marketplace": "Plugin marketplaces",
    "skill": "Skills",
    "subagent": "Subagents",
    "command": "Custom commands",
    "extension": "Extensions",
    "settings_file": "Settings files",
}
KIND_ORDER = list(KIND_TITLES)

PLATFORM_TITLES = {
    "claude_code": "Claude Code",
    "copilot": "GitHub Copilot",
    "vscode": "VS Code",
    "codex": "OpenAI Codex",
    "gemini_cli": "Gemini CLI",
    "cursor": "Cursor",
}
PLATFORM_ORDER = list(PLATFORM_TITLES)


def _shorten(path: str, home: Path) -> str:
    home_str = str(home)
    if path == home_str:
        return "~"
    for sep in ("/", "\\"):
        if path.startswith(home_str + sep):
            return "~" + sep + path[len(home_str) + 1 :]
    return path


def _clean(value: Any, home: Path) -> Any:
    if isinstance(value, str):
        return _shorten(value, home)
    if isinstance(value, list):
        return [_clean(v, home) for v in value]
    if isinstance(value, dict):
        return {k: _clean(v, home) for k, v in value.items()}
    return value


def to_json(result: ScanResult, ctx: ScanContext) -> str:
    payload = {
        "tool": "moatline",
        "version": __version__,
        "read_only": True,
        "project": _shorten(str(ctx.project), ctx.home),
        "summary": result.count_by_kind(),
        "assets": [_clean(a.to_dict(), ctx.home) for a in result.assets],
        "errors": [_clean(e.to_dict(), ctx.home) for e in result.errors],
        "scanned_files": [_shorten(p, ctx.home) for p in result.scanned_files],
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def _describe(asset: Asset) -> str:
    d = asset.details
    if asset.kind == "mcp_server":
        bits = [d.get("transport", "?")]
        if d.get("command"):
            bits.append("runs: " + " ".join([d["command"], *d.get("args", [])]))
        if d.get("url"):
            bits.append("url: " + d["url"])
        if d.get("env_names"):
            bits.append("env: " + ", ".join(d["env_names"]))
        if d.get("header_names"):
            bits.append("headers: " + ", ".join(d["header_names"]))
        if d.get("token_env_var"):
            bits.append("token from env: " + d["token_env_var"])
        if d.get("input_names"):
            bits.append("prompts for: " + ", ".join(d["input_names"]))
        for flag in ("trust", "enabled", "disabled"):
            if flag in d:
                bits.append(f"{flag}: {_yes_no(d[flag])}")
        for key in ("tools", "includeTools", "enabled_tools", "allowedTools"):
            if isinstance(d.get(key), list):
                bits.append("tools allowed: " + (", ".join(d[key]) or "none"))
        for key in ("excludeTools", "disabled_tools"):
            if isinstance(d.get(key), list) and d[key]:
                bits.append("tools blocked: " + ", ".join(d[key]))
        if d.get("extension"):
            bits.append("from extension: " + d["extension"])
        if d.get("project_path"):
            bits.append("project: " + d["project_path"])
        if d.get("also_used_by"):
            bits.append("also used by: " + d["also_used_by"])
        return "; ".join(bits)
    if asset.kind == "hook":
        action = d.get("command") or d.get("url") or d.get("prompt_preview") or ""
        extra = f"; onFailure: {d['onFailure']}" if "onFailure" in d else ""
        return f"{d.get('type', 'command')}: {action}{extra}"
    if asset.kind == "plugin":
        versions = ", ".join(d.get("installed_versions", [])) or "unknown version"
        return f"installed: {versions}"
    if asset.kind == "marketplace":
        return d.get("source", "")
    if asset.kind == "settings_file":
        return _describe_settings(d)
    if asset.kind == "extension":
        bits = [f"version {d['version']}"] if d.get("version") else []
        bits.append(f"MCP servers: {d.get('mcp_server_count', 0)}")
        bits.append(f"hooks: {d.get('hook_count', 0)}")
        if d.get("has_env_file"):
            bits.append("has its own .env file")
        return "; ".join(bits)
    if asset.kind == "skill":
        return f"{d.get('bundled_files', 0)} bundled file(s)"
    return ""


_SETTING_LABELS = {
    "default_permission_mode": "default mode",
    "approval_policy": "approval policy",
    "sandbox_mode": "sandbox mode",
    "sandbox_network_access": "sandbox network access",
    "default_approval_mode": "default approval mode",
    "sandbox_enabled": "sandbox",
    "sandbox": "sandbox",
    "folder_trust": "folder trust",
    "disable_yolo_mode": "YOLO mode blocked",
    "secure_mode": "secure mode",
    "auto_accept": "auto-accept",
    "env_var_redaction": "env var redaction",
    "hook_count": "hooks",
    "mcp_server_count": "MCP servers",
    "auto_allowed_tools": "tools that skip approval",
    "mcp_allowed": "MCP allowlist entries",
    "mcp_excluded": "MCP blocklist entries",
}


def _yes_no(value: Any) -> str:
    if value is True:
        return "on"
    if value is False:
        return "off"
    return str(value)


def _describe_settings(d: dict[str, Any]) -> str:
    bits: list[str] = []
    for key, value in d.items():
        if value is None or value == [] or value == "":
            continue
        if key == "allow_rules":
            bits.append(f"allow rules: {len(value)}")
        elif key == "ask_rule_count" or key == "deny_rule_count":
            continue
        elif key == "env_names":
            bits.append("env: " + ", ".join(value))
        elif key == "enabled_plugins":
            bits.append("plugins on: " + ", ".join(value))
        elif key == "profiles":
            bits.append("profiles: " + ", ".join(value))
        elif isinstance(value, (list, dict)):
            continue
        else:
            bits.append(f"{_SETTING_LABELS.get(key, key)}: {_yes_no(value)}")
    if "sandbox_enabled" not in d or d.get("sandbox_enabled") is None:
        if "default_permission_mode" in d:  # Claude Code settings file without a sandbox setting
            bits.append("sandbox: not set")
    return "; ".join(bits)


def to_text(result: ScanResult, ctx: ScanContext) -> str:
    lines: list[str] = []
    lines.append(f"Moatline Agent Inventory Scan v{__version__}")
    lines.append(f"Project folder: {_shorten(str(ctx.project), ctx.home)}")
    lines.append(f"Files read: {len(result.scanned_files)}")
    lines.append("")

    counts = result.count_by_kind()
    if not result.assets:
        lines.append("No AI-agent configuration found.")
    else:
        lines.append("Summary")
        tools = [PLATFORM_TITLES.get(p, p) for p in PLATFORM_ORDER if any(a.platform == p for a in result.assets)]
        lines.append(f"  AI tools found: {', '.join(tools)}")
        for kind in KIND_ORDER:
            if kind in counts:
                lines.append(f"  {KIND_TITLES[kind]}: {counts[kind]}")

    found = {a.platform for a in result.assets}
    platforms = [p for p in PLATFORM_ORDER if p in found] + sorted(found - set(PLATFORM_ORDER))
    for platform in platforms:
        lines.append("")
        lines.append(f"== {PLATFORM_TITLES.get(platform, platform)} ==")
        for kind in KIND_ORDER:
            items = [a for a in result.assets if a.platform == platform and a.kind == kind]
            if not items:
                continue
            lines.append("")
            lines.append(KIND_TITLES[kind])
            for asset in items:
                # Shorten home paths inside each detail before joining them into one line.
                cleaned = Asset(
                    asset.kind, asset.platform, asset.scope, asset.name, asset.source,
                    _clean(asset.details, ctx.home),
                )
                desc = _describe(cleaned)
                lines.append(f"  - {asset.name} ({asset.scope})" + (f": {desc}" if desc else ""))
                lines.append(f"      from {_shorten(asset.source, ctx.home)}")

    if result.errors:
        lines.append("")
        lines.append("Files that could not be read")
        for error in result.errors:
            lines.append(f"  - {_shorten(error.source, ctx.home)}: {error.reason}")

    lines.append("")
    lines.append("This scan is read-only. No files were changed and nothing was sent over the network.")
    lines.append("Secret values are never shown; only the names of environment variables and headers.")
    return "\n".join(lines)
