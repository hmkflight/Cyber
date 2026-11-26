"""Week 4: risk checks. Each check has a case that should fire and one that shouldn't."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import FAKE_SECRETS
from moatline.checks import CHECKS, run_checks, unpinned_package
from moatline.cli import main
from moatline.discovery import run_all
from moatline.discovery.base import ScanContext
from moatline.models import Asset, ScanResult
from moatline.report import to_json, to_text


def _write(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = data if isinstance(data, str) else json.dumps(data, indent=2)
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def empty_env(tmp_path: Path) -> ScanContext:
    home = tmp_path / "home" / "hudson"
    project = tmp_path / "work" / "app"
    home.mkdir(parents=True)
    project.mkdir(parents=True)
    return ScanContext(home=home, project=project, platform_os="darwin", env={}, system_dirs={})


def _findings(ctx: ScanContext, check_id: str | None = None):
    found = run_checks(run_all(ctx), ctx)
    return [f for f in found if check_id is None or f.check_id == check_id]


def _safe_claude_settings(ctx: ScanContext) -> None:
    _write(ctx.home / ".claude" / "settings.json", {"sandbox": {"enabled": True}})


# Clean machine ----------------------------------------------------------------


def test_clean_machine_has_no_findings(empty_env):
    _safe_claude_settings(empty_env)
    _write(
        empty_env.home / ".claude.json",
        {"mcpServers": {"docs": {"command": "npx", "args": ["-y", "@acme/docs-mcp@1.4.2"], "env": {"API_KEY": "${API_KEY}"}}}},
    )
    assert _findings(empty_env) == []
    assert "No risky settings found." in to_text(run_all(empty_env), empty_env)


# ML001 auto-updating packages -------------------------------------------------


@pytest.mark.parametrize(
    "command, args, expected",
    [
        ("npx", ["-y", "@playwright/mcp@latest"], "@playwright/mcp@latest"),
        ("npx", ["-y", "@modelcontextprotocol/server-github"], "@modelcontextprotocol/server-github"),
        ("npx", ["mcp-remote@^1.2.0", "https://x.example"], "mcp-remote@^1.2.0"),
        ("/usr/local/bin/npx", ["chrome-devtools-mcp"], "chrome-devtools-mcp"),
        ("npx.cmd", ["-y", "tavily-mcp"], "tavily-mcp"),
        ("pnpm", ["dlx", "some-mcp"], "some-mcp"),
        ("uvx", ["mcp-server-fetch"], "mcp-server-fetch"),
        ("uv", ["tool", "run", "mcp-server-git"], "mcp-server-git"),
        ("docker", ["run", "-i", "--rm", "-e", "GITHUB_TOKEN", "ghcr.io/github/github-mcp-server"], "ghcr.io/github/github-mcp-server"),
        ("docker", ["run", "-i", "mcp/fetch:latest"], "mcp/fetch:latest"),
    ],
)
def test_unpinned_package_detected(command, args, expected):
    assert unpinned_package(command, args) == expected


@pytest.mark.parametrize(
    "command, args",
    [
        ("npx", ["-y", "@playwright/mcp@0.0.41"]),
        ("npx", ["mcp-remote@1.2.3"]),
        ("npx", ["./local-server.js"]),
        ("node", ["server.js"]),
        ("uvx", ["mcp-server-fetch==2025.4.7"]),
        ("uvx", ["--from", "git+https://github.com/acme/tool@v1.2.0", "tool"]),
        ("uv", ["run", "server.py"]),
        ("docker", ["run", "-i", "mcp/fetch:1.0.0"]),
        ("docker", ["run", "-i", "mcp/fetch@sha256:abc123"]),
        ("python3", ["-m", "my_server"]),
    ],
)
def test_pinned_or_local_package_not_flagged(command, args):
    assert unpinned_package(command, args) is None


def test_ml001_finding_from_config(empty_env):
    _safe_claude_settings(empty_env)
    _write(empty_env.home / ".claude.json", {"mcpServers": {"pw": {"command": "npx", "args": ["@playwright/mcp@latest"]}}})
    [finding] = _findings(empty_env, "ML001")
    assert finding.severity == "medium"
    assert finding.asset == "pw"
    assert finding.owasp.startswith("ASI04")
    assert "@playwright/mcp@latest" in finding.evidence


# ML002 acts without asking ----------------------------------------------------


def test_claude_bypass_permissions_is_high(empty_env):
    _write(empty_env.home / ".claude" / "settings.json", {"permissions": {"defaultMode": "bypassPermissions"}, "sandbox": {"enabled": True}})
    [finding] = _findings(empty_env, "ML002")
    assert finding.severity == "high"
    assert finding.owasp.startswith("ASI02")


def test_claude_broad_bash_rule_is_medium_but_narrow_rule_is_fine(empty_env):
    _write(empty_env.home / ".claude" / "settings.json", {"permissions": {"allow": ["Bash", "Bash(npm test *)"]}, "sandbox": {"enabled": True}})
    [finding] = _findings(empty_env, "ML002")
    assert finding.severity == "medium"
    assert finding.evidence == "allow: Bash"

    _write(empty_env.home / ".claude" / "settings.json", {"permissions": {"allow": ["Bash(npm test *)"]}, "sandbox": {"enabled": True}})
    assert _findings(empty_env, "ML002") == []


def test_codex_never_ask_and_gemini_modes(empty_env):
    _write(empty_env.home / ".codex" / "config.toml", 'approval_policy = "never"\n')
    _write(empty_env.home / ".gemini" / "settings.json", {"general": {"defaultApprovalMode": "yolo"}})
    found = {(f.platform, f.severity) for f in _findings(empty_env, "ML002")}
    assert found == {("codex", "high"), ("gemini_cli", "high")}


def test_codex_on_request_is_fine(empty_env):
    _write(empty_env.home / ".codex" / "config.toml", 'approval_policy = "on-request"\nsandbox_mode = "workspace-write"\n')
    assert _findings(empty_env) == []


def test_trusted_server_is_flagged(empty_env):
    _write(empty_env.home / ".gemini" / "settings.json", {"mcpServers": {"w": {"command": "node", "args": ["w.js"], "trust": True}}})
    [finding] = _findings(empty_env, "ML002")
    assert finding.asset == "w"
    assert finding.severity == "medium"


# ML003 sandbox ----------------------------------------------------------------


def test_codex_full_access_is_high(empty_env):
    _write(empty_env.home / ".codex" / "config.toml", 'sandbox_mode = "danger-full-access"\n')
    [finding] = _findings(empty_env, "ML003")
    assert finding.severity == "high"
    assert finding.owasp.startswith("ASI05")


def test_claude_sandbox_off_is_one_low_finding(empty_env):
    _write(empty_env.home / ".claude" / "settings.json", {"permissions": {"allow": []}})
    _write(empty_env.project / ".claude" / "settings.json", {})
    [finding] = _findings(empty_env, "ML003")
    assert finding.severity == "low"
    assert finding.scope == "user"


def test_claude_sandbox_reported_even_without_a_settings_file(empty_env):
    _write(empty_env.home / ".claude.json", {"mcpServers": {"docs": {"type": "http", "url": "https://docs.example.com/mcp"}}})
    [finding] = _findings(empty_env, "ML003")
    assert finding.source.endswith("settings.json")


def test_claude_sandbox_on_only_in_the_project_is_still_reported(empty_env):
    _write(empty_env.home / ".claude" / "settings.json", {})
    _write(empty_env.project / ".claude" / "settings.json", {"sandbox": {"enabled": True}})
    [finding] = _findings(empty_env, "ML003")
    assert finding.title == "Claude Code's sandbox is only on for this project"


def test_claude_sandbox_on_for_the_user_is_fine(empty_env):
    _write(empty_env.home / ".claude" / "settings.json", {"sandbox": {"enabled": True}})
    _write(empty_env.project / ".claude" / "settings.json", {})
    assert _findings(empty_env, "ML003") == []


def test_gemini_folder_trust_off(empty_env):
    _write(empty_env.home / ".gemini" / "settings.json", {"security": {"folderTrust": {"enabled": False}}})
    [finding] = _findings(empty_env, "ML003")
    assert finding.platform == "gemini_cli"


# ML004 / ML005 secrets ------------------------------------------------------------


def test_literal_secret_in_env_and_header_is_high(empty_env):
    _safe_claude_settings(empty_env)
    _write(
        empty_env.home / ".cursor" / "mcp.json",
        {
            "mcpServers": {
                "linear": {"url": "https://mcp.linear.app/sse", "headers": {"Authorization": f"Bearer {FAKE_SECRETS[0]}"}},
                "ok": {"url": "https://mcp.example.com/sse", "headers": {"Authorization": "Bearer ${env:LINEAR_TOKEN}"}},
                "plain": {"command": "node", "args": ["s.js"], "env": {"DISABLE_AUTH": "false", "AUTH_URL": "https://auth.example.com"}},
            }
        },
    )
    [finding] = _findings(empty_env, "ML004")
    assert finding.asset == "linear"
    assert finding.severity == "high"
    assert finding.evidence == "names: Authorization"
    assert FAKE_SECRETS[0] not in finding.to_dict().__repr__()


def test_camel_case_secret_names_are_found(empty_env):
    _write(
        empty_env.home / ".cursor" / "mcp.json",
        {"mcpServers": {"x": {"command": "node", "args": ["x.js"], "env": {"accessToken": "plainFAKE", "clientSecret": "alsoFAKE", "monkeyMode": "plain"}}}},
    )
    [finding] = _findings(empty_env, "ML004")
    assert finding.evidence == "names: accessToken, clientSecret"


def test_secret_in_url_query_is_found(empty_env):
    _write(empty_env.home / ".gemini" / "settings.json", {"mcpServers": {"r": {"httpUrl": f"https://mcp.example.com/mcp?token={FAKE_SECRETS[3]}"}}})
    [finding] = _findings(empty_env, "ML004")
    assert "inside its URL" in finding.evidence


def test_harmless_url_query_is_not_a_secret(empty_env):
    _write(empty_env.home / ".gemini" / "settings.json", {"mcpServers": {"r": {"httpUrl": "https://mcp.example.com/mcp?region=us"}}})
    assert _findings(empty_env, "ML004") == []


def test_literal_secret_in_claude_settings_env(empty_env):
    _write(empty_env.home / ".claude" / "settings.json", {"env": {"ANTHROPIC_AUTH_TOKEN": FAKE_SECRETS[0], "MAX_THINKING_TOKENS": "8000"}, "sandbox": {"enabled": True}})
    [finding] = _findings(empty_env, "ML004")
    assert finding.evidence == "names: ANTHROPIC_AUTH_TOKEN"


def test_secret_in_command_line(empty_env):
    _safe_claude_settings(empty_env)
    _write(empty_env.project / ".mcp.json", {"mcpServers": {"db": {"command": "node", "args": ["s.js", "--api-key", FAKE_SECRETS[4]]}}})
    [finding] = _findings(empty_env, "ML005")
    assert finding.asset == "db"
    assert "[REDACTED]" in finding.evidence
    assert FAKE_SECRETS[4] not in finding.evidence


# ML006 reach --------------------------------------------------------------------


def test_trading_server_registered_for_home_folder_is_high(empty_env):
    _safe_claude_settings(empty_env)
    _write(
        empty_env.home / ".claude.json",
        {"projects": {str(empty_env.home): {"mcpServers": {"robinhood-trading": {"type": "http", "url": "https://mcp.example.com/rh"}}}}},
    )
    [finding] = _findings(empty_env, "ML006")
    assert finding.severity == "high"
    assert finding.owasp.startswith("ASI03")
    assert str(empty_env.home) not in finding.evidence


def test_ordinary_server_for_home_folder_is_medium_and_for_a_project_is_fine(empty_env):
    _safe_claude_settings(empty_env)
    _write(
        empty_env.home / ".claude.json",
        {
            "projects": {
                str(empty_env.home): {"mcpServers": {"notes": {"type": "http", "url": "https://notes.example.com/mcp"}}},
                str(empty_env.home / "code" / "shop"): {"mcpServers": {"stripe": {"type": "http", "url": "https://mcp.stripe.com"}}},
            }
        },
    )
    [finding] = _findings(empty_env, "ML006")
    assert (finding.asset, finding.severity) == ("notes", "medium")


def test_high_impact_user_server_is_low(empty_env):
    _write(empty_env.home / ".codex" / "config.toml", '[mcp_servers.gmail]\nurl = "https://gmail.example.com/mcp"\n')
    [finding] = _findings(empty_env, "ML006")
    assert finding.severity == "low"


# ML007 project hooks ------------------------------------------------------------


def test_project_hook_is_flagged_and_user_hook_is_not(empty_env):
    _write(empty_env.project / ".claude" / "settings.json", {"sandbox": {"enabled": True}, "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "./setup.sh"}]}]}})
    _write(empty_env.home / ".claude" / "settings.json", {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "say done"}]}]}})
    [finding] = _findings(empty_env, "ML007")
    assert finding.scope == "project"
    assert finding.evidence == "SessionStart: ./setup.sh"


# ML008 plain http ---------------------------------------------------------------


def test_plain_http_remote_is_flagged_but_localhost_is_fine(empty_env):
    _write(
        empty_env.home / ".cursor" / "mcp.json",
        {
            "mcpServers": {
                "remote": {"url": "http://mcp.example.com/sse"},
                "local": {"url": "http://localhost:3845/mcp"},
                "loop": {"url": "http://127.0.0.1:8080/mcp"},
                "v6": {"url": "http://[::1]:9000/mcp"},
                "tls": {"url": "https://mcp.example.com/sse"},
            }
        },
    )
    [finding] = _findings(empty_env, "ML008")
    assert finding.asset == "remote"
    assert finding.owasp.startswith("ASI07")


# ML009 third-party plugins ------------------------------------------------------


def test_third_party_plugin_flagged_official_not(empty_env):
    _safe_claude_settings(empty_env)
    cache = empty_env.home / ".claude" / "plugins" / "cache"
    (cache / "claude-plugins-official" / "code-review" / "1.0.0").mkdir(parents=True)
    (cache / "knowledge-work-plugins" / "marketing" / "1.0.0").mkdir(parents=True)
    (cache / "someone-seo" / "claude-seo" / "2.0.0").mkdir(parents=True)
    [finding] = _findings(empty_env, "ML009")
    assert finding.asset == "claude-seo@someone-seo"
    assert finding.severity == "low"


# ML010 shared credentials --------------------------------------------------------


def test_same_key_in_two_tools_is_flagged(empty_env):
    _safe_claude_settings(empty_env)
    _write(empty_env.home / ".claude.json", {"mcpServers": {"github": {"command": "node", "args": ["gh.js"], "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}}}})
    _write(
        empty_env.home / ".codex" / "config.toml",
        '[mcp_servers.gh]\ncommand = "node"\nargs = ["gh.js"]\nenv_vars = ["GITHUB_TOKEN"]\n',
    )
    [finding] = _findings(empty_env, "ML010")
    assert finding.title == "GITHUB_TOKEN is shared by 2 AI tools"
    assert "Claude Code 'github'" in finding.evidence and "OpenAI Codex 'gh'" in finding.evidence


def test_key_used_by_one_tool_only_is_fine(empty_env):
    _safe_claude_settings(empty_env)
    _write(
        empty_env.home / ".claude.json",
        {"mcpServers": {
            "a": {"command": "node", "args": ["a.js"], "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}},
            "b": {"command": "node", "args": ["b.js"], "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}", "REGION": "us"}},
        }},
    )
    assert _findings(empty_env, "ML010") == []


# Report, CLI and safety ---------------------------------------------------------


def test_every_finding_is_complete_and_sorted(fake_env):
    findings = run_checks(run_all(fake_env), fake_env)
    assert findings
    order = {"high": 0, "medium": 1, "low": 2}
    assert [order[f.severity] for f in findings] == sorted(order[f.severity] for f in findings)
    for f in findings:
        assert f.check_id.startswith("ML")
        assert f.owasp.startswith("ASI")
        assert f.why.endswith(".") and f.fix.endswith(".")


def test_findings_never_show_secrets_or_username(fake_env):
    result = run_all(fake_env)
    text = to_text(result, fake_env)
    data = to_json(result, fake_env)
    assert "Findings:" in text
    assert json.loads(data)["findings"]
    for output in (text, data):
        for secret in FAKE_SECRETS:
            assert secret not in output
        assert str(fake_env.home) not in output


def test_home_path_hidden_inside_commands(empty_env):
    script = (empty_env.home / "hooks" / "check.py").as_posix()
    _write(empty_env.project / ".claude" / "settings.json", {"sandbox": {"enabled": True}, "hooks": {"Stop": [{"hooks": [{"type": "command", "command": f"python3 {script}"}]}]}})
    result = run_all(empty_env)
    for output in (to_text(result, empty_env), to_json(result, empty_env)):
        assert empty_env.home.as_posix() not in output
        assert "python3 ~/hooks/check.py" in output


def test_terminal_escape_codes_are_not_printed(empty_env):
    name = "evil\x1b[2J\x1b[32mNo risky settings found\u202e"
    _write(empty_env.project / ".mcp.json", {"mcpServers": {name: {"command": "node", "args": ["x.js"]}}})
    text = to_text(run_all(empty_env), empty_env)
    assert "\x1b" not in text and "\u202e" not in text
    assert "evil\\x{1b}[2J" in text


def test_broken_check_becomes_an_error_not_a_crash(empty_env, monkeypatch):
    def broken(result, ctx):
        raise ValueError("boom")

    monkeypatch.setattr("moatline.checks.CHECKS", [broken, *CHECKS])
    _write(empty_env.home / ".codex" / "config.toml", 'approval_policy = "never"\n')
    result = run_all(empty_env)
    findings = run_checks(result, empty_env)
    assert any(f.check_id == "ML002" for f in findings)
    assert any("broken" in e.source for e in result.errors)


def test_malformed_url_port_does_not_crash(empty_env):
    _write(empty_env.home / ".cursor" / "mcp.json", {"mcpServers": {"bad": {"url": "http://mcp.example.com:abc/sse"}}})
    servers = [a for a in run_all(empty_env).assets if a.kind == "mcp_server"]
    assert [s.name for s in servers] == ["bad"]


def test_checks_ignore_odd_detail_values(empty_env):
    result = ScanResult()
    result.assets.append(Asset("mcp_server", "claude_code", "user", "x", "/x.json", {"command": "npx", "args": [None, 3]}))
    result.assets.append(Asset("hook", "copilot", "project", "h", "/h.json", {}))
    run_checks(result, empty_env)  # must not raise


def _use_fake_machine(monkeypatch, ctx: ScanContext) -> None:
    """Make the CLI scan only the fake folders, never this computer's real system folders."""
    monkeypatch.setattr(ScanContext, "from_environment", classmethod(lambda cls, project=None, home=None: ctx))


def test_fail_on_exit_codes(fake_env, monkeypatch, capsys):
    _use_fake_machine(monkeypatch, fake_env)
    base = ["scan", "--home", str(fake_env.home), "--project", str(fake_env.project)]
    assert main(base) == 0
    assert main([*base, "--fail-on", "high"]) == 1
    capsys.readouterr()


def test_fail_on_passes_when_clean(empty_env, monkeypatch, capsys):
    _use_fake_machine(monkeypatch, empty_env)
    _safe_claude_settings(empty_env)
    code = main(["scan", "--home", str(empty_env.home), "--project", str(empty_env.project), "--fail-on", "low"])
    capsys.readouterr()
    assert code == 0
