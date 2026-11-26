from __future__ import annotations

import json
from pathlib import Path

from moatline.discovery import base, claude_code
from moatline.discovery.base import ScanContext


def _ctx(tmp_path: Path) -> ScanContext:
    home = tmp_path / "home"
    project = tmp_path / "proj"
    (home / ".claude").mkdir(parents=True)
    project.mkdir()
    return ScanContext(home=home, project=project, env={}, system_dirs={})


def test_broken_json_becomes_an_error_not_a_crash(tmp_path):
    ctx = _ctx(tmp_path)
    (ctx.home / ".claude" / "settings.json").write_text("{ not json, }", encoding="utf-8")
    result = claude_code.scan(ctx)
    assert result.assets == []
    assert len(result.errors) == 1
    assert "not valid JSON" in result.errors[0].reason


def test_wrong_shapes_are_handled(tmp_path):
    ctx = _ctx(tmp_path)
    (ctx.home / ".claude" / "settings.json").write_text(json.dumps(["a", "list"]), encoding="utf-8")
    (ctx.project / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"bad": "not an object", "ok": {"command": "x"}}}), encoding="utf-8"
    )
    (ctx.home / ".claude.json").write_text(
        json.dumps({"mcpServers": [], "projects": {"/p": "nope"}, "hooks": 5}), encoding="utf-8"
    )
    result = claude_code.scan(ctx)
    assert [a.name for a in result.assets if a.kind == "mcp_server"] == ["ok"]
    reasons = " ".join(e.reason for e in result.errors)
    assert "expected a JSON object" in reasons
    assert "'bad' is not an object" in reasons


def test_non_utf8_file(tmp_path):
    ctx = _ctx(tmp_path)
    (ctx.project / ".mcp.json").write_bytes(b"\xff\xfe\x00bad")
    result = claude_code.scan(ctx)
    assert any("UTF-8" in e.reason or "JSON" in e.reason for e in result.errors)


def test_oversized_file_is_skipped(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    (ctx.project / ".mcp.json").write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")
    monkeypatch.setattr(base, "MAX_FILE_BYTES", 5)
    result = claude_code.scan(ctx)
    assert any("larger than" in e.reason for e in result.errors)


def test_deeply_nested_json_is_skipped(tmp_path):
    ctx = _ctx(tmp_path)
    (ctx.project / ".mcp.json").write_text("[" * 200_000 + "]" * 200_000, encoding="utf-8")
    result = claude_code.scan(ctx)
    assert any("nested too deeply" in e.reason for e in result.errors)


def test_hidden_skill_is_still_found(tmp_path):
    ctx = _ctx(tmp_path)
    hidden = ctx.home / ".claude" / "skills" / ".sneaky"
    hidden.mkdir(parents=True)
    (hidden / "SKILL.md").write_text("hidden\n", encoding="utf-8")
    skills = [a.name for a in claude_code.scan(ctx).assets if a.kind == "skill"]
    assert skills == [".sneaky"]


def test_malformed_hooks_are_ignored(tmp_path):
    ctx = _ctx(tmp_path)
    (ctx.home / ".claude" / "settings.json").write_text(
        json.dumps({"hooks": {"PreToolUse": "nope", "Stop": [5, {"hooks": "x"}, {"hooks": [7, {"command": "ok"}]}]}}),
        encoding="utf-8",
    )
    hooks = [a for a in claude_code.scan(ctx).assets if a.kind == "hook"]
    assert len(hooks) == 1
    assert hooks[0].details["command"] == "ok"
