"""Week 3: discovery for GitHub Copilot, VS Code, OpenAI Codex, Gemini CLI and Cursor."""

from __future__ import annotations

from pathlib import Path

from moatline.discovery import codex, copilot, cursor, gemini_cli, run_all, vscode
from moatline.discovery.base import ScanContext, strip_jsonc
from moatline.report import to_text


def _assets(result, kind):
    return [a for a in result.assets if a.kind == kind]


def _servers(result):
    return {a.name: a for a in _assets(result, "mcp_server")}


# GitHub Copilot ---------------------------------------------------------------


def test_copilot_mcp_servers(fake_env):
    servers = _servers(copilot.scan(fake_env))
    assert set(servers) == {"playwright", "context7"}
    assert servers["playwright"].details["transport"] == "stdio"  # "local" means stdio
    assert servers["playwright"].details["tools"] == ["*"]
    assert servers["context7"].details["header_names"] == ["CONTEXT7_API_KEY"]


def test_copilot_hooks_in_flat_and_nested_form_and_policy(fake_env):
    hooks = _assets(copilot.scan(fake_env), "hook")
    by_scope = {h.scope: h for h in hooks}
    assert set(by_scope) == {"user", "project", "managed"}
    assert by_scope["user"].details["command"] == "./audit.sh --token [REDACTED]"
    assert by_scope["user"].details["timeoutSec"] == 10
    assert by_scope["project"].details["matcher"] == "shell"
    assert by_scope["managed"].details["type"] == "http"
    assert by_scope["managed"].details["header_names"] == ["X-Key"]


def test_copilot_home_override(tmp_path: Path):
    custom = tmp_path / "copilot-home"
    custom.mkdir()
    (custom / "mcp-config.json").write_text('{"mcpServers": {"x": {"command": "y"}}}', encoding="utf-8")
    ctx = ScanContext(home=tmp_path / "h", project=tmp_path, env={"COPILOT_HOME": str(custom)}, system_dirs={})
    assert set(_servers(copilot.scan(ctx))) == {"x"}


# VS Code ----------------------------------------------------------------------


def test_vscode_reads_json_with_comments(fake_env):
    servers = _servers(vscode.scan(fake_env))
    assert set(servers) == {"github", "fs", "local-db"}
    assert servers["github"].scope == "user"
    assert servers["github"].details["input_names"] == ["github-pat"]
    assert servers["fs"].details["env_names"] == ["SECRET_THING"]
    assert "input_names" not in servers["fs"].details  # fs doesn't use the github-pat prompt
    assert servers["local-db"].scope == "project"


def test_vscode_linux_and_windows_paths(tmp_path: Path):
    for platform_os, rel in (("linux", ".config/Code/User/mcp.json"), ("win32", "AppData/Roaming/Code - Insiders/User/mcp.json")):
        home = tmp_path / platform_os
        target = home / rel
        target.parent.mkdir(parents=True)
        target.write_text('{"servers": {"s": {"command": "c"}}}', encoding="utf-8")
        ctx = ScanContext(home=home, project=tmp_path, platform_os=platform_os, env={}, system_dirs={})
        assert set(_servers(vscode.scan(ctx))) == {"s"}, platform_os


def test_strip_jsonc_keeps_strings_intact():
    text = '{"url": "https://x.example/a//b", "note": "/* not a comment */", // real comment\n "list": [1, 2,],}'
    assert strip_jsonc(text) == '{"url": "https://x.example/a//b", "note": "/* not a comment */", \n "list": [1, 2]}'


# OpenAI Codex -----------------------------------------------------------------


def test_codex_toml_servers_settings_and_hooks(fake_env):
    result = codex.scan(fake_env)
    servers = _servers(result)
    assert set(servers) == {"context7", "figma"}
    assert servers["context7"].details["env_names"] == ["LOCAL_TOKEN", "MY_ENV_VAR"]
    assert servers["figma"].details["transport"] == "http"
    assert servers["figma"].details["token_env_var"] == "FIGMA_OAUTH_TOKEN"
    assert servers["figma"].details["header_names"] == ["X-Api-Key", "X-Figma-Region"]
    assert servers["figma"].details["enabled_tools"] == ["open", "screenshot"]

    settings = _assets(result, "settings_file")[0]
    assert settings.details["approval_policy"] == "never"
    assert settings.details["sandbox_mode"] == "danger-full-access"

    hooks = _assets(result, "hook")
    assert sorted(h.details["event"] for h in hooks) == ["PreToolUse", "SessionStart"]


def test_codex_bad_toml_is_an_error(tmp_path: Path):
    home = tmp_path / "h"
    (home / ".codex").mkdir(parents=True)
    (home / ".codex" / "config.toml").write_text("approval_policy = \n", encoding="utf-8")
    ctx = ScanContext(home=home, project=tmp_path, env={}, system_dirs={})
    result = codex.scan(ctx)
    assert result.assets == []
    assert "not valid TOML" in result.errors[0].reason


# Gemini CLI -------------------------------------------------------------------


def test_gemini_servers_settings_hooks_and_extensions(fake_env):
    result = gemini_cli.scan(fake_env)
    servers = _servers(result)
    assert set(servers) == {"weather", "remote", "gcp-tools"}
    assert servers["weather"].details["trust"] is True
    assert servers["weather"].details["excludeTools"] == ["delete"]
    assert servers["remote"].details["url"] == "https://mcp.example.com/mcp?[query removed]"
    assert servers["gcp-tools"].scope == "extension"

    settings = {s.scope: s for s in _assets(result, "settings_file")}
    assert settings["user"].details["default_approval_mode"] == "auto_edit"
    assert settings["user"].details["folder_trust"] is False
    assert settings["user"].details["auto_allowed_tools"] == 1
    assert settings["managed"].details["disable_yolo_mode"] is True

    extension = _assets(result, "extension")[0]
    assert extension.name == "gcp"
    assert extension.details["has_env_file"] is True
    assert extension.details["hook_count"] == 1

    assert {h.details["event"] for h in _assets(result, "hook")} == {"BeforeTool", "AfterTool"}


def test_gemini_system_settings_env_override(tmp_path: Path):
    custom = tmp_path / "custom-system.json"
    custom.write_text('{"mcpServers": {"corp": {"url": "https://corp.example/mcp"}}}', encoding="utf-8")
    ctx = ScanContext(home=tmp_path / "h", project=tmp_path, env={"GEMINI_CLI_SYSTEM_SETTINGS_PATH": str(custom)}, system_dirs={})
    servers = _servers(gemini_cli.scan(ctx))
    assert servers["corp"].scope == "managed"


# Cursor -----------------------------------------------------------------------


def test_cursor_servers_and_hooks(fake_env):
    result = cursor.scan(fake_env)
    servers = _servers(result)
    assert servers["linear"].scope == "user"
    assert servers["linear"].details["header_names"] == ["Authorization"]
    assert servers["local"].scope == "project"
    hooks = _assets(result, "hook")
    assert sorted((h.scope, h.details["event"]) for h in hooks) == [
        ("managed", "beforeShellExecution"),
        ("user", "beforeMCPExecution"),
        ("user", "beforeShellExecution"),
    ]


# Whole report -----------------------------------------------------------------


def test_report_lists_every_tool(fake_env):
    output = to_text(run_all(fake_env), fake_env)
    assert "AI tools found: Claude Code, GitHub Copilot, VS Code, OpenAI Codex, Gemini CLI, Cursor" in output
    for title in ("== GitHub Copilot ==", "== VS Code ==", "== OpenAI Codex ==", "== Gemini CLI ==", "== Cursor =="):
        assert title in output
    assert "approval policy: never" in output
    assert "trust: on" in output
    assert "also used by: GitHub Copilot" in output


def test_one_broken_tool_does_not_stop_the_others(fake_env, monkeypatch):
    def _boom(ctx):
        raise RuntimeError("bug")

    monkeypatch.setitem(__import__("moatline.discovery", fromlist=["DISCOVERERS"]).DISCOVERERS, "codex", _boom)
    result = run_all(fake_env)
    assert any(e.platform == "codex" and "internal error" in e.reason for e in result.errors)
    assert any(a.platform == "cursor" for a in result.assets)
