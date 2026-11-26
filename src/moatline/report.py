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
    "settings_file": "Settings files",
}
KIND_ORDER = list(KIND_TITLES)

PLATFORM_TITLES = {"claude_code": "Claude Code"}


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
        if d.get("project_path"):
            bits.append("project: " + d["project_path"])
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
        bits = []
        if d.get("default_permission_mode"):
            bits.append(f"default mode: {d['default_permission_mode']}")
        bits.append(f"sandbox: {'on' if d.get('sandbox_enabled') else 'off or not set'}")
        bits.append(f"allow rules: {len(d.get('allow_rules', []))}")
        bits.append(f"hooks: {d.get('hook_count', 0)}")
        if d.get("env_names"):
            bits.append("env: " + ", ".join(d["env_names"]))
        if d.get("enabled_plugins"):
            bits.append("plugins on: " + ", ".join(d["enabled_plugins"]))
        return "; ".join(bits)
    if asset.kind == "skill":
        return f"{d.get('bundled_files', 0)} bundled file(s)"
    return ""


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
        for kind in KIND_ORDER:
            if kind in counts:
                lines.append(f"  {KIND_TITLES[kind]}: {counts[kind]}")

    platforms = sorted({a.platform for a in result.assets})
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
