"""The scanner's three promises: no network, no writes, no leaked secrets."""

from __future__ import annotations

import ast
import hashlib
import json
import socket
from pathlib import Path

import pytest

from conftest import FAKE_SECRETS
from moatline.discovery import run_all
from moatline.report import to_json, to_text

SRC = Path(__file__).resolve().parents[1] / "src" / "moatline"
FORBIDDEN_MODULES = {
    "socket", "ssl", "http", "urllib.request", "requests", "httpx", "aiohttp",
    "ftplib", "smtplib", "telnetlib", "subprocess", "shutil",
}


def test_source_never_imports_network_or_process_modules():
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                assert not any(name == m or name.startswith(m + ".") for m in FORBIDDEN_MODULES), (
                    f"{path.name} imports {name}"
                )


def test_scan_makes_no_network_connections(fake_env, monkeypatch):
    def _blocked(*args, **kwargs):
        raise AssertionError("the scanner tried to open a network connection")

    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    result = run_all(fake_env)
    to_text(result, fake_env)
    to_json(result, fake_env)


def _snapshot(root: Path) -> dict[str, str]:
    return {
        str(p): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def test_scan_changes_no_files(fake_env):
    root = fake_env.home.parents[1]
    before = _snapshot(root)
    result = run_all(fake_env)
    to_text(result, fake_env)
    to_json(result, fake_env)
    assert _snapshot(root) == before


@pytest.mark.parametrize("render", [to_text, to_json])
def test_no_secret_value_appears_in_any_report(fake_env, render):
    output = render(run_all(fake_env), fake_env)
    for secret in FAKE_SECRETS:
        assert secret not in output, f"leaked {secret}"
    # Names are still useful and must be present.
    for name in ["GITHUB_TOKEN", "OPENAI_API_KEY", "Authorization", "DB_URL"]:
        assert name in output


def test_text_report_hides_the_username(fake_env):
    output = to_text(run_all(fake_env), fake_env)
    assert str(fake_env.home) not in output
    assert "project: ~" in output


def test_reports_hide_the_username(fake_env):
    output = to_json(run_all(fake_env), fake_env)
    payload = json.loads(output)
    assert str(fake_env.home) not in json.dumps(payload)
    assert any(p.startswith("~") and p.endswith(".claude.json") for p in payload["scanned_files"])
