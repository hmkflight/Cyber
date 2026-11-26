"""Discover Claude Code configuration.

Locations come from the Claude Code docs (Nov 2026):
- Settings: managed-settings.json (+ managed-settings.d/*.json) in the system
  folder, ~/.claude/settings.json, .claude/settings.json and
  .claude/settings.local.json in the project. CLAUDE_CONFIG_DIR replaces ~/.claude.
- MCP servers: ~/.claude.json top-level "mcpServers" (user scope),
  ~/.claude.json "projects"[<path>]["mcpServers"] (local scope), .mcp.json in
  the project root (project scope), managed-mcp.json in the system folder.
- Hooks: the "hooks" key inside any settings file.
- Skills, subagents, commands: skills/<name>/SKILL.md, agents/*.md and
  commands/*.md under ~/.claude and the project's .claude folder.
- Plugins: installed copies under ~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from moatline.discovery.base import ScanContext, list_children, read_json
from moatline.models import Asset, ScanError, ScanResult
from moatline.redact import names_only, redact_list, redact_text, redact_url

PLATFORM = "claude_code"

_SYSTEM_DIRS = {
    "darwin": Path("/Library/Application Support/ClaudeCode"),
    "linux": Path("/etc/claude-code"),
    "win32": Path("C:/Program Files/ClaudeCode"),
}


def _system_dir(ctx: ScanContext) -> Path | None:
    if ctx.system_dirs is not None:
        return ctx.system_dirs.get(PLATFORM)
    key = "linux" if ctx.platform_os.startswith("linux") else ctx.platform_os
    return _SYSTEM_DIRS.get(key)


def _config_dir(ctx: ScanContext) -> Path:
    override = ctx.env.get("CLAUDE_CONFIG_DIR")
    return Path(override).expanduser() if override else ctx.home / ".claude"


def scan(ctx: ScanContext) -> ScanResult:
    result = ScanResult()
    config_dir = _config_dir(ctx)
    system_dir = _system_dir(ctx)

    # Settings files, most powerful first.
    settings_files: list[tuple[str, Path]] = []
    if system_dir is not None:
        settings_files.append(("managed", system_dir / "managed-settings.json"))
        for extra in list_children(system_dir / "managed-settings.d", PLATFORM, result):
            if extra.suffix == ".json":
                settings_files.append(("managed", extra))
    settings_files.append(("user", config_dir / "settings.json"))
    settings_files.append(("project", ctx.project / ".claude" / "settings.json"))
    settings_files.append(("local", ctx.project / ".claude" / "settings.local.json"))

    for scope, path in settings_files:
        data = read_json(path, PLATFORM, result)
        if data is None:
            continue
        if not isinstance(data, dict):
            result.errors.append(ScanError(PLATFORM, str(path), "expected a JSON object"))
            continue
        _scan_settings(data, scope, path, result)

    # MCP servers.
    for global_file in _unique([ctx.home / ".claude.json", config_dir / ".claude.json"]):
        data = read_json(global_file, PLATFORM, result)
        if isinstance(data, dict):
            _scan_mcp_block(data.get("mcpServers"), "user", global_file, result)
            projects = data.get("projects")
            if isinstance(projects, dict):
                for project_path, project_state in projects.items():
                    if isinstance(project_state, dict):
                        _scan_mcp_block(
                            project_state.get("mcpServers"),
                            "local",
                            global_file,
                            result,
                            extra={"project_path": str(project_path)},
                        )

    project_mcp = ctx.project / ".mcp.json"
    data = read_json(project_mcp, PLATFORM, result)
    if isinstance(data, dict):
        _scan_mcp_block(data.get("mcpServers"), "project", project_mcp, result)

    if system_dir is not None:
        managed_mcp = system_dir / "managed-mcp.json"
        data = read_json(managed_mcp, PLATFORM, result)
        if isinstance(data, dict):
            _scan_mcp_block(data.get("mcpServers"), "managed", managed_mcp, result)

    # Skills, subagents and commands.
    for scope, base in (("user", config_dir), ("project", ctx.project / ".claude")):
        _scan_skills(base / "skills", scope, result)
        _scan_markdown_folder(base / "agents", "subagent", scope, result)
        _scan_markdown_folder(base / "commands", "command", scope, result)

    # Installed plugins.
    _scan_plugin_cache(config_dir / "plugins" / "cache", result)

    return result


def _unique(paths: list[Path]) -> list[Path]:
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in paths:
        if path not in seen:
            seen.add(path)
            unique.append(path)
    return unique


def _scan_settings(data: dict[str, Any], scope: str, path: Path, result: ScanResult) -> None:
    permissions = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
    sandbox = data.get("sandbox") if isinstance(data.get("sandbox"), dict) else {}
    enabled_plugins = data.get("enabledPlugins") if isinstance(data.get("enabledPlugins"), dict) else {}
    marketplaces = data.get("extraKnownMarketplaces") if isinstance(data.get("extraKnownMarketplaces"), dict) else {}

    hooks_block = data.get("hooks") if isinstance(data.get("hooks"), dict) else {}
    hook_count = _scan_hooks(hooks_block, scope, path, result)

    details: dict[str, Any] = {
        "default_permission_mode": permissions.get("defaultMode"),
        "allow_rules": redact_list(permissions.get("allow", []) if isinstance(permissions.get("allow"), list) else []),
        "ask_rule_count": len(permissions.get("ask", [])) if isinstance(permissions.get("ask"), list) else 0,
        "deny_rule_count": len(permissions.get("deny", [])) if isinstance(permissions.get("deny"), list) else 0,
        "sandbox_enabled": sandbox.get("enabled"),
        "env_names": names_only(data.get("env")),
        "enabled_plugins": sorted(name for name, on in enabled_plugins.items() if on is True),
        "hook_count": hook_count,
    }
    for flag in ("disableAllHooks", "allowManagedHooksOnly", "allowManagedMcpServersOnly", "strictKnownMarketplaces"):
        if flag in data:
            details[flag] = data[flag] if isinstance(data[flag], bool) else "set"

    result.assets.append(Asset("settings_file", PLATFORM, scope, path.name, str(path), details))

    for name, entry in marketplaces.items():
        source = entry.get("source") if isinstance(entry, dict) else entry
        result.assets.append(
            Asset("marketplace", PLATFORM, scope, str(name), str(path), {"source": _describe_source(source)})
        )


def _describe_source(source: Any) -> str:
    if isinstance(source, dict):
        parts = []
        for key in ("source", "repo", "url", "path", "package"):
            if key in source:
                value = str(source[key])
                parts.append(f"{key}={redact_url(value) if key == 'url' else redact_text(value)}")
        return ", ".join(parts) or "unknown"
    if isinstance(source, str):
        return redact_url(source)
    return "unknown"


def _scan_hooks(hooks_block: dict[str, Any], scope: str, path: Path, result: ScanResult) -> int:
    count = 0
    for event, groups in hooks_block.items():
        if not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            matcher = group.get("matcher", "")
            handlers = group.get("hooks") if isinstance(group.get("hooks"), list) else []
            for handler in handlers:
                if not isinstance(handler, dict):
                    continue
                count += 1
                hook_type = handler.get("type", "command")
                details: dict[str, Any] = {
                    "event": str(event),
                    "matcher": redact_text(str(matcher)),
                    "type": str(hook_type),
                }
                if "command" in handler:
                    details["command"] = redact_text(str(handler["command"]))
                if "url" in handler:
                    details["url"] = redact_url(str(handler["url"]))
                    details["header_names"] = names_only(handler.get("headers"))
                if "prompt" in handler:
                    details["prompt_preview"] = redact_text(str(handler["prompt"])[:120])
                for key in ("timeout", "onFailure"):
                    if key in handler:
                        details[key] = handler[key]
                label = f"{event}" + (f" [{details['matcher']}]" if matcher else "")
                result.assets.append(Asset("hook", PLATFORM, scope, label, str(path), details))
    return count


def _scan_mcp_block(
    block: Any,
    scope: str,
    path: Path,
    result: ScanResult,
    extra: dict[str, Any] | None = None,
) -> None:
    if not isinstance(block, dict):
        return
    for name, server in block.items():
        if not isinstance(server, dict):
            result.errors.append(ScanError(PLATFORM, str(path), f"MCP server '{name}' is not an object"))
            continue
        transport = server.get("type") or ("stdio" if "command" in server else "unknown")
        details: dict[str, Any] = {"transport": str(transport)}
        if "command" in server:
            details["command"] = redact_text(str(server["command"]))
            args = server.get("args")
            details["args"] = redact_list(args) if isinstance(args, list) else []
        if "url" in server:
            details["url"] = redact_url(str(server["url"]))
        details["env_names"] = names_only(server.get("env"))
        details["header_names"] = names_only(server.get("headers"))
        if extra:
            details.update(extra)
        result.assets.append(Asset("mcp_server", PLATFORM, scope, str(name), str(path), details))


def _scan_skills(folder: Path, scope: str, result: ScanResult) -> None:
    for skill_dir in list_children(folder, PLATFORM, result):
        skill_file = skill_dir / "SKILL.md"
        if skill_dir.is_dir() and skill_file.is_file():
            extra_files = [p.name for p in list_children(skill_dir, PLATFORM, result) if p.name != "SKILL.md"]
            result.assets.append(
                Asset(
                    "skill",
                    PLATFORM,
                    scope,
                    skill_dir.name,
                    str(skill_file),
                    {"bundled_files": len(extra_files)},
                )
            )


def _scan_markdown_folder(folder: Path, kind: str, scope: str, result: ScanResult) -> None:
    for item in list_children(folder, PLATFORM, result):
        if item.is_file() and item.suffix == ".md":
            result.assets.append(Asset(kind, PLATFORM, scope, item.stem, str(item), {}))


def _scan_plugin_cache(cache: Path, result: ScanResult) -> None:
    for marketplace in list_children(cache, PLATFORM, result):
        if not marketplace.is_dir():
            continue
        for plugin in list_children(marketplace, PLATFORM, result):
            if not plugin.is_dir():
                continue
            versions = [v.name for v in list_children(plugin, PLATFORM, result) if v.is_dir()]
            result.assets.append(
                Asset(
                    "plugin",
                    PLATFORM,
                    "plugin",
                    f"{plugin.name}@{marketplace.name}",
                    str(plugin),
                    {"marketplace": marketplace.name, "installed_versions": versions},
                )
            )
