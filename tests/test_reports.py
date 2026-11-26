"""Week 5: Markdown and SARIF reports, grouped findings, and saving to a file."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

import pytest

from conftest import FAKE_SECRETS
from moatline.checks import RULES, run_checks
from moatline.cli import FORMATS, main
from moatline.discovery import run_all
from moatline.discovery.base import ScanContext
from moatline.markdown import code, md, to_markdown
from moatline.report import group_findings, to_json, to_text
from moatline.sarif import to_sarif

NOW = datetime(2026, 11, 26, 10, 0)


def _write(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


@pytest.fixture
def empty_env(tmp_path: Path) -> ScanContext:
    home = tmp_path / "home" / "hudson"
    project = tmp_path / "work" / "app"
    home.mkdir(parents=True)
    project.mkdir(parents=True)
    return ScanContext(home=home, project=project, platform_os="darwin", env={}, system_dirs={})


def _two_third_party_plugins(ctx: ScanContext) -> None:
    _write(ctx.home / ".claude" / "settings.json", {"sandbox": {"enabled": True}})
    cache = ctx.home / ".claude" / "plugins" / "cache"
    (cache / "someone-seo" / "claude-seo" / "2.0.0").mkdir(parents=True)
    (cache / "marketingskills" / "marketing-skills" / "1.0.0").mkdir(parents=True)


def _without_code_spans(text: str) -> str:
    return re.sub(r"(`+).*?\1", "", text)


# Every format: no secrets, no username -------------------------------------------


@pytest.mark.parametrize("fmt", list(FORMATS))
def test_no_format_shows_secrets_or_the_home_folder(fake_env, fmt):
    output = FORMATS[fmt](run_all(fake_env), fake_env)
    for secret in FAKE_SECRETS:
        assert secret not in output
    assert str(fake_env.home) not in output
    assert fake_env.home.as_posix() not in output


# Grouping ---------------------------------------------------------------------------


def test_same_kind_findings_are_grouped(empty_env):
    _two_third_party_plugins(empty_env)
    result = run_all(empty_env)
    findings = run_checks(result, empty_env)
    assert len(findings) == 2
    [group] = group_findings(findings)
    assert group.title == "2 plugins come from third-party marketplaces"
    text = to_text(result, empty_env, findings)
    assert "[LOW] 2 plugins come from third-party marketplaces" in text
    assert "Findings: 0 high, 0 medium, 2 low" in text  # counts stay per finding
    assert len(json.loads(to_json(result, empty_env, findings))["findings"]) == 2  # JSON keeps every finding


def test_one_finding_keeps_its_own_title(empty_env):
    _write(empty_env.home / ".claude" / "settings.json", {"sandbox": {"enabled": True}})
    (empty_env.home / ".claude" / "plugins" / "cache" / "someone-seo" / "claude-seo" / "2.0.0").mkdir(parents=True)
    [group] = group_findings(run_checks(run_all(empty_env), empty_env))
    assert group.title == "Plugin 'claude-seo@someone-seo' comes from a third-party marketplace"


def test_exposed_keys_come_before_other_high_findings(fake_env):
    findings = run_checks(run_all(fake_env), fake_env)
    highs = [f.check_id for f in findings if f.severity == "high"]
    assert highs[0] == "ML004"


# Markdown ---------------------------------------------------------------------------


def test_markdown_report_layout(fake_env):
    report = to_markdown(run_all(fake_env), fake_env, now=NOW)
    for heading in (
        "# Moatline AI agent security report",
        "## At a glance",
        "## Start here: your top 3 fixes",
        "## All findings",
        "### High: fix these first",
        "## What's installed",
        "## About this report",
    ):
        assert heading in report
    assert "**Scanned:** November 26, 2026" in report
    top = report.split("## Start here: your top 3 fixes")[1].split("## All findings")[0]
    assert [line[:3] for line in top.strip().splitlines()] == ["1. ", "2. ", "3. "]


def test_markdown_for_a_clean_machine(empty_env):
    _write(empty_env.home / ".claude" / "settings.json", {"sandbox": {"enabled": True}})
    report = to_markdown(run_all(empty_env), empty_env, now=NOW)
    assert "No risky settings found." in report
    assert "## All findings" not in report


def test_markdown_shows_secret_endings_only_for_long_keys(empty_env):
    _write(
        empty_env.home / ".claude" / "settings.json",
        {"env": {"OPENAI_API_KEY": FAKE_SECRETS[0], "DB_PASSWORD": "hunter2-FAKE"}, "sandbox": {"enabled": True}},
    )
    report = to_markdown(run_all(empty_env), empty_env, now=NOW)
    assert "OPENAI_API_KEY (ends in ...1234)" in report
    assert "DB_PASSWORD (ends" not in report
    assert "hunter2-FAKE" not in report and "FAKE" not in report.split("ends in")[0][-40:]


def test_markdown_escapes_hostile_names(empty_env):
    hostile = "x](https://evil.example) <img src=x onerror=alert(1)> **bold** | col"
    _write(empty_env.home / ".claude" / "settings.json", {"sandbox": {"enabled": True}})
    _write(empty_env.home / ".claude.json", {"mcpServers": {hostile: {"command": "npx", "args": ["evil-mcp@latest"]}}})
    report = to_markdown(run_all(empty_env), empty_env, now=NOW)
    outside_code = _without_code_spans(report)
    # Only escaped forms (\] \< \*) may appear outside code spans.
    assert not re.search(r"(?<!\\)\]\(https://evil", outside_code)
    assert not re.search(r"(?<!\\)<img", outside_code)
    assert not re.search(r"(?<!\\)\*\*bold", outside_code)
    # Table rows still have exactly 5 cells.
    for line in report.splitlines():
        if line.startswith("| MCP servers |"):
            assert len(re.split(r"(?<!\\)\|", line)) == 7


def test_markdown_helpers():
    assert md("a_b *c* [d](e) <f>") == r"a\_b \*c\* \[d\](e) \<f\>"
    assert code("plain") == "`plain`"
    assert code("has ` tick") == "``has ` tick``"
    assert code("`edge`") == "`` `edge` ``"
    assert "\x1b" not in md("evil\x1b[2J") and "\x1b" not in code("evil\x1b[2J")


# SARIF ------------------------------------------------------------------------------


def test_sarif_structure(fake_env):
    result = run_all(fake_env)
    findings = run_checks(result, fake_env)
    sarif = json.loads(to_sarif(result, fake_env, findings))
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    [run] = sarif["runs"]
    rules = run["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == list(RULES)
    for rule in rules:
        assert float(rule["properties"]["security-severity"]) > 0
        assert rule["defaultConfiguration"]["level"] in {"error", "warning", "note"}
    assert len(run["results"]) == len(findings)
    for item in run["results"]:
        assert rules[item["ruleIndex"]]["id"] == item["ruleId"]
        assert item["level"] in {"error", "warning", "note"}
        assert item["message"]["text"]
        assert item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_sarif_paths(fake_env):
    sarif = json.loads(to_sarif(run_all(fake_env), fake_env))
    locations = [r["locations"][0]["physicalLocation"]["artifactLocation"] for r in sarif["runs"][0]["results"]]
    in_project = [loc for loc in locations if loc.get("uriBaseId") == "%SRCROOT%"]
    assert {"uri": ".mcp.json", "uriBaseId": "%SRCROOT%"} in in_project
    assert all(loc["uri"].startswith("~/") for loc in locations if "uriBaseId" not in loc and "system" not in loc["uri"])
    assert any("Application%20Support" in loc["uri"] for loc in locations)


def test_sarif_fingerprints_are_stable(fake_env):
    first = json.loads(to_sarif(run_all(fake_env), fake_env))
    second = json.loads(to_sarif(run_all(fake_env), fake_env))
    prints = [r["partialFingerprints"]["moatlineFinding/v1"] for r in first["runs"][0]["results"]]
    assert prints == [r["partialFingerprints"]["moatlineFinding/v1"] for r in second["runs"][0]["results"]]
    assert len(set(prints)) == len(prints)


# Saving to a file ---------------------------------------------------------------------


def _use_fake_machine(monkeypatch, ctx: ScanContext) -> None:
    monkeypatch.setattr(ScanContext, "from_environment", classmethod(lambda cls, project=None, home=None: ctx))


def _digest(root: Path) -> dict[str, str]:
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob("*")) if p.is_file()}


def test_output_saves_a_new_file_and_changes_nothing_else(fake_env, tmp_path, monkeypatch, capsys):
    _use_fake_machine(monkeypatch, fake_env)
    target = tmp_path / "out" / "report.md"
    target.parent.mkdir()
    before = _digest(fake_env.home.parents[1])
    code_ = main(["scan", "--format", "markdown", "--output", str(target)])
    captured = capsys.readouterr()
    assert code_ == 0
    assert captured.out == ""
    assert "Report saved to" in captured.err
    assert target.read_text(encoding="utf-8").startswith("# Moatline AI agent security report")
    after = _digest(fake_env.home.parents[1])
    after.pop(str(target))
    assert after == before  # the report is the only new file; nothing else changed


def test_output_never_overwrites(fake_env, tmp_path, monkeypatch, capsys):
    _use_fake_machine(monkeypatch, fake_env)
    target = tmp_path / "keep.md"
    target.write_text("my notes", encoding="utf-8")
    assert main(["scan", "--format", "markdown", "--output", str(target)]) == 2
    assert target.read_text(encoding="utf-8") == "my notes"
    assert "already exists" in capsys.readouterr().err


def test_output_to_a_missing_folder_is_an_error_not_a_crash(fake_env, tmp_path, monkeypatch, capsys):
    _use_fake_machine(monkeypatch, fake_env)
    assert main(["scan", "--output", str(tmp_path / "nope" / "r.txt")]) == 2
    assert "could not save" in capsys.readouterr().err


def test_every_format_works_from_the_command_line(fake_env, monkeypatch, capsys):
    _use_fake_machine(monkeypatch, fake_env)
    for fmt in FORMATS:
        assert main(["scan", "--format", fmt]) == 0
        out = capsys.readouterr().out
        if fmt in ("json", "sarif"):
            json.loads(out)
        assert out.strip()
