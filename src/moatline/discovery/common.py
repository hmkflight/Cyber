"""Parsers shared by every AI tool.

Most tools describe MCP servers and hooks in similar shapes with different key
names. These functions accept all the known variants, so each tool's module
only has to say where its files are.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from moatline.models import Asset, ScanError, ScanResult
from moatline.redact import literal_secret_names, names_only, redact_list, redact_text, redact_url, url_has_secret

_STDIO = {"stdio", "local"}

# Safe, non-secret settings worth showing for an MCP server, by tool key name.
_SERVER_FLAGS = (
    "trust",  # Gemini CLI: skip confirmation for this server's tools
    "enabled",  # Codex, Cursor
    "disabled",
    "timeout",
    "cwd",
)
# Lists of tool names that limit what a server can do.
_TOOL_FILTERS = ("tools", "includeTools", "excludeTools", "enabled_tools", "disabled_tools", "allowedTools")


def _transport(server: dict[str, Any]) -> str:
    declared = str(server.get("type") or server.get("transport") or "").lower()
    if declared in _STDIO:
        return "stdio"
    if declared:
        return declared
    if "command" in server:
        return "stdio"
    if "httpUrl" in server:
        return "http"
    if "url" in server or "serverUrl" in server:
        return "http"
    return "unknown"


def scan_mcp_block(
    block: Any,
    platform: str,
    scope: str,
    path: Path,
    result: ScanResult,
    extra: dict[str, Any] | None = None,
) -> int:
    """Add one Asset per MCP server in ``block`` (a name -> config mapping)."""
    if not isinstance(block, dict):
        return 0
    count = 0
    for name, server in block.items():
        if not isinstance(server, dict):
            result.errors.append(ScanError(platform, str(path), f"MCP server '{name}' is not an object"))
            continue
        count += 1
        details: dict[str, Any] = {"transport": _transport(server)}
        if "command" in server:
            details["command"] = redact_text(str(server["command"]))
            args = server.get("args")
            details["args"] = redact_list(args) if isinstance(args, list) else []
        for url_key in ("httpUrl", "url", "serverUrl"):
            if url_key in server:
                details["url"] = redact_url(str(server[url_key]))
                if url_has_secret(str(server[url_key])):
                    details["url_has_secret"] = True
                break
        details["env_names"] = sorted(
            set(names_only(server.get("env"))) | set(_string_list(server.get("env_vars")))
        )
        details["header_names"] = sorted(
            set(names_only(server.get("headers")))
            | set(names_only(server.get("http_headers")))
            | set(names_only(server.get("env_http_headers")))
        )
        # env_http_headers holds variable names, not values, so it is left out here.
        literal = sorted(
            set(literal_secret_names(server.get("env")))
            | set(literal_secret_names(server.get("headers")))
            | set(literal_secret_names(server.get("http_headers")))
        )
        if literal:
            details["literal_secret_names"] = literal
        if server.get("bearer_token_env_var"):
            details["token_env_var"] = redact_text(str(server["bearer_token_env_var"]))
        for flag in _SERVER_FLAGS:
            if flag in server and isinstance(server[flag], (bool, int, float, str)):
                details[flag] = redact_text(server[flag]) if isinstance(server[flag], str) else server[flag]
        for key in _TOOL_FILTERS:
            if isinstance(server.get(key), list):
                details[key] = redact_list(server[key])
        if extra:
            details.update(extra)
        result.assets.append(Asset("mcp_server", platform, scope, str(name), str(path), details))
    return count


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if isinstance(v, (str, int))]
    return []


def _handler_details(event: str, matcher: Any, handler: dict[str, Any]) -> dict[str, Any]:
    details: dict[str, Any] = {
        "event": str(event),
        "matcher": redact_text(str(matcher)) if matcher not in (None, "") else "",
        "type": str(handler.get("type", "command")),
    }
    # Different tools name the thing a hook runs differently.
    for key in ("command", "bash", "powershell", "exec"):
        if key in handler and isinstance(handler[key], (str, list)):
            value = handler[key]
            text = " ".join(map(str, value)) if isinstance(value, list) else str(value)
            if key == "exec" and isinstance(handler.get("args"), list):
                text = " ".join([text, *redact_list(handler["args"])])
            details["command"] = redact_text(text)
            break
    if "url" in handler:
        details["url"] = redact_url(str(handler["url"]))
        details["header_names"] = names_only(handler.get("headers"))
        literal = literal_secret_names(handler.get("headers"))
        if literal:
            details["literal_secret_names"] = literal
        if url_has_secret(str(handler["url"])):
            details["url_has_secret"] = True
    if "prompt" in handler:
        details["prompt_preview"] = redact_text(str(handler["prompt"])[:120])
    for key in ("timeout", "timeoutSec", "onFailure", "failClosed", "name"):
        if key in handler and isinstance(handler[key], (bool, int, float, str)):
            details[key] = redact_text(handler[key]) if isinstance(handler[key], str) else handler[key]
    return details


def scan_hooks_block(hooks_block: Any, platform: str, scope: str, path: Path, result: ScanResult) -> int:
    """Add one Asset per hook handler.

    Accepts both shapes in use today:
    - nested: {"PreToolUse": [{"matcher": "Bash", "hooks": [{...}]}]}  (Claude Code, Codex, Gemini CLI)
    - flat:   {"preToolUse": [{"type": "command", "bash": "..."}]}      (Copilot, Cursor)
    """
    if not isinstance(hooks_block, dict):
        return 0
    count = 0
    for event, entries in hooks_block.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if isinstance(entry.get("hooks"), list):
                matcher = entry.get("matcher", "")
                handlers = [h for h in entry["hooks"] if isinstance(h, dict)]
            elif "hooks" in entry:
                continue  # malformed nested entry
            else:
                matcher = entry.get("matcher", "")
                handlers = [entry]
            for handler in handlers:
                count += 1
                details = _handler_details(str(event), matcher, handler)
                label = str(event) + (f" [{details['matcher']}]" if details["matcher"] else "")
                result.assets.append(Asset("hook", platform, scope, label, str(path), details))
    return count


def settings_asset(
    platform: str,
    scope: str,
    path: Path,
    details: dict[str, Any],
    result: ScanResult,
    name: str | None = None,
) -> None:
    result.assets.append(Asset("settings_file", platform, scope, name or path.name, str(path), details))


def dig(data: Any, *keys: str) -> Any:
    """Safely read data["a"]["b"]... and return None when any step is missing."""
    for key in keys:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def as_scalar(value: Any) -> Any:
    """Keep simple values; redact strings; drop anything complex."""
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return redact_text(value)
    return None
