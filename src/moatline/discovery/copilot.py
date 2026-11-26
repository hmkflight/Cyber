"""Discover GitHub Copilot CLI / Copilot agent configuration.

Locations (GitHub docs, Nov 2026):
- MCP servers: $COPILOT_HOME/mcp-config.json, falling back to
  ~/.copilot/mcp-config.json ("mcpServers"). The project-root .mcp.json is
  shared with Claude Code and reported there.
- Hooks: ~/.copilot/hooks/*.json, ~/.copilot/settings.json ("hooks"),
  .github/hooks/*.json, .github/copilot/settings.json and settings.local.json.
- Admin policy hooks (Copilot CLI): /etc/github-copilot/policy.d/*.json on
  Linux and macOS, C:\\ProgramData\\GitHub\\Copilot\\policy.d\\*.json on Windows.
"""

from __future__ import annotations

from pathlib import Path

from moatline.discovery.base import ScanContext, json_files, read_json, system_dir
from moatline.discovery.common import as_scalar, scan_hooks_block, scan_mcp_block, settings_asset
from moatline.models import ScanResult

PLATFORM = "copilot"

_POLICY_DIRS = {
    "darwin": Path("/etc/github-copilot/policy.d"),
    "linux": Path("/etc/github-copilot/policy.d"),
    "win32": Path("C:/ProgramData/GitHub/Copilot/policy.d"),
}


def _copilot_home(ctx: ScanContext) -> Path:
    override = ctx.env.get("COPILOT_HOME")
    return Path(override).expanduser() if override else ctx.home / ".copilot"


def _hook_file(path: Path, scope: str, result: ScanResult) -> None:
    data = read_json(path, PLATFORM, result, allow_comments=True)
    if isinstance(data, dict):
        scan_hooks_block(data.get("hooks"), PLATFORM, scope, path, result)


def _settings_file(path: Path, scope: str, result: ScanResult) -> None:
    data = read_json(path, PLATFORM, result, allow_comments=True)
    if not isinstance(data, dict):
        return
    hook_count = scan_hooks_block(data.get("hooks"), PLATFORM, scope, path, result)
    details = {"hook_count": hook_count}
    for key in ("disableAllHooks", "trusted_folders", "allowed_urls", "denied_urls"):
        if key in data:
            value = data[key]
            details[key] = len(value) if isinstance(value, list) else as_scalar(value)
    settings_asset(PLATFORM, scope, path, details, result)


def scan(ctx: ScanContext) -> ScanResult:
    result = ScanResult()
    home = _copilot_home(ctx)

    mcp_file = home / "mcp-config.json"
    data = read_json(mcp_file, PLATFORM, result, allow_comments=True)
    if isinstance(data, dict):
        scan_mcp_block(data.get("mcpServers"), PLATFORM, "user", mcp_file, result)

    _settings_file(home / "settings.json", "user", result)
    for hook_file in json_files(home / "hooks", PLATFORM, result):
        _hook_file(hook_file, "user", result)

    github = ctx.project / ".github"
    for hook_file in json_files(github / "hooks", PLATFORM, result):
        _hook_file(hook_file, "project", result)
    _settings_file(github / "copilot" / "settings.json", "project", result)
    _settings_file(github / "copilot" / "settings.local.json", "local", result)

    policy = system_dir(ctx, "copilot_policy", _POLICY_DIRS)
    if policy is not None:
        for hook_file in json_files(policy, PLATFORM, result):
            _hook_file(hook_file, "managed", result)

    return result
