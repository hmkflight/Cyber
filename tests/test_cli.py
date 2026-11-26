from __future__ import annotations

import json

from moatline.cli import main


def test_scan_json_runs(fake_env, monkeypatch, capsys):
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    code = main(["scan", "--home", str(fake_env.home), "--project", str(fake_env.project), "--format", "json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["read_only"] is True
    assert payload["summary"]["mcp_server"] >= 3


def test_scan_text_runs(fake_env, monkeypatch, capsys):
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    code = main(["scan", "--home", str(fake_env.home), "--project", str(fake_env.project)])
    out = capsys.readouterr().out
    assert code == 0
    assert "== Claude Code ==" in out
    assert "MCP servers" in out
    assert "read-only" in out


def test_missing_project_folder(tmp_path, capsys):
    code = main(["scan", "--project", str(tmp_path / "nope")])
    assert code == 2


def test_no_command_prints_help(capsys):
    assert main([]) == 0
    assert "scan" in capsys.readouterr().out
