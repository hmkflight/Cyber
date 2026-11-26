from __future__ import annotations

import json
from pathlib import Path

from moatline.discovery import claude_code, run_all
from moatline.discovery.base import ScanContext


def _by(result, kind):
    return {a.name: a for a in result.assets if a.kind == kind}


def test_finds_every_mcp_server_with_the_right_scope(fake_env):
    result = claude_code.scan(fake_env)
    servers = _by(result, "mcp_server")
    assert set(servers) == {"github", "stripe", "db", "company-docs"}
    assert servers["github"].scope == "user"
    assert servers["stripe"].scope == "local"
    assert servers["db"].scope == "project"
    assert servers["company-docs"].scope == "managed"
    assert servers["github"].details["transport"] == "stdio"
    assert servers["stripe"].details["transport"] == "http"


def test_mcp_servers_report_env_and_header_names_only(fake_env):
    servers = _by(claude_code.scan(fake_env), "mcp_server")
    assert servers["github"].details["env_names"] == ["GITHUB_TOKEN"]
    assert servers["stripe"].details["header_names"] == ["Authorization"]
    assert servers["db"].details["env_names"] == ["DB_URL"]


def test_finds_hooks_from_settings(fake_env):
    hooks = [a for a in claude_code.scan(fake_env).assets if a.kind == "hook"]
    assert len(hooks) == 3
    events = sorted(h.details["event"] for h in hooks)
    assert events == ["PostToolUse", "PreToolUse", "PreToolUse"]
    http_hook = next(h for h in hooks if h.details["type"] == "http")
    assert http_hook.details["onFailure"] == "block"
    assert http_hook.details["url"] == "https://policy.example.com/check?[query removed]"


def test_settings_files_and_flags(fake_env):
    settings = [a for a in claude_code.scan(fake_env).assets if a.kind == "settings_file"]
    scopes = sorted(s.scope for s in settings)
    assert scopes == ["managed", "project", "user"]
    user = next(s for s in settings if s.scope == "user")
    assert user.details["default_permission_mode"] == "bypassPermissions"
    assert user.details["enabled_plugins"] == ["code-review@claude-plugins-official"]
    assert user.details["env_names"] == ["OPENAI_API_KEY"]
    managed = next(s for s in settings if s.scope == "managed")
    assert managed.details["allowManagedHooksOnly"] is True
    project = next(s for s in settings if s.scope == "project")
    assert project.details["sandbox_enabled"] is True


def test_skills_subagents_commands_plugins_marketplaces(fake_env):
    result = claude_code.scan(fake_env)
    assert _by(result, "skill")["pdf"].details["bundled_files"] == 1
    assert "reviewer" in _by(result, "subagent")
    assert _by(result, "command")["deploy"].scope == "project"
    plugin = _by(result, "plugin")["code-review@claude-plugins-official"]
    assert plugin.details["installed_versions"] == ["1.2.0"]
    assert _by(result, "marketplace")["acme"].details["source"] == "source=github, repo=acme/plugins"


def test_claude_config_dir_override(tmp_path: Path):
    home = tmp_path / "home"
    custom = tmp_path / "custom-claude"
    project = tmp_path / "proj"
    project.mkdir(parents=True)
    custom.mkdir(parents=True)
    (custom / "settings.json").write_text(json.dumps({"permissions": {"defaultMode": "plan"}}), encoding="utf-8")
    ctx = ScanContext(home=home, project=project, env={"CLAUDE_CONFIG_DIR": str(custom)}, system_dirs={})
    settings = [a for a in claude_code.scan(ctx).assets if a.kind == "settings_file"]
    assert len(settings) == 1
    assert settings[0].details["default_permission_mode"] == "plan"


def test_empty_machine_finds_nothing(tmp_path: Path):
    ctx = ScanContext(home=tmp_path / "h", project=tmp_path, env={}, system_dirs={})
    result = run_all(ctx)
    assert result.assets == []
    assert result.errors == []
