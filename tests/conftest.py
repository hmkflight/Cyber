"""Fake home, project and system folders for tests. Never touch the real machine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from moatline.discovery.base import ScanContext

# Every fake secret placed in the fixtures. Tests assert none of these ever
# appear in any report.
FAKE_SECRETS = [
    "sk-test-FAKEabcdefghijklmnop1234",
    "ghp_FAKEFAKEFAKEFAKEFAKE1234",
    "sk-test-FAKEstripeheader0000000",
    "sk-test-FAKEurlquerykey99999999",
    "shortpw42",
    "FAKEKEY1234567890abcdefFAKEKEY99",
    "hunter2-FAKE",
]


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


@pytest.fixture
def fake_env(tmp_path: Path) -> ScanContext:
    home = tmp_path / "home" / "hudson"
    project = tmp_path / "work" / "app"
    system = tmp_path / "system" / "ClaudeCode"
    project.mkdir(parents=True)

    _write_json(
        home / ".claude" / "settings.json",
        {
            "permissions": {
                "defaultMode": "bypassPermissions",
                "allow": ["Bash(npm run *)", "WebFetch(domain:example.com)"],
                "deny": ["Read(./.env)"],
            },
            "env": {"OPENAI_API_KEY": FAKE_SECRETS[0]},
            "enabledPlugins": {"code-review@claude-plugins-official": True, "old@acme": False},
            "extraKnownMarketplaces": {"acme": {"source": {"source": "github", "repo": "acme/plugins"}}},
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            {
                                "type": "command",
                                "command": f"python3 ~/hooks/check.py --token={FAKE_SECRETS[0]}",
                                "timeout": 10,
                            },
                            {
                                "type": "http",
                                "url": "https://policy.example.com/check?key=abc123",
                                "headers": {"Authorization": f"Bearer {FAKE_SECRETS[2]}"},
                                "onFailure": "block",
                            },
                        ],
                    }
                ],
                "PostToolUse": [
                    {"hooks": [{"type": "command", "command": "export DB_PASSWORD=hunter2-FAKE && ./log.sh"}]}
                ],
            },
        },
    )

    _write_json(
        home / ".claude.json",
        {
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": {"GITHUB_TOKEN": FAKE_SECRETS[1]},
                }
            },
            "projects": {
                str(project): {
                    "mcpServers": {
                        "stripe": {
                            "type": "http",
                            "url": f"https://user:pw@mcp.stripe.com/v1?key={FAKE_SECRETS[3]}",
                            "headers": {"Authorization": f"Bearer {FAKE_SECRETS[2]}"},
                        }
                    }
                }
            },
        },
    )

    _write_json(
        project / ".mcp.json",
        {
            "mcpServers": {
                "db": {
                    "command": "node",
                    "args": ["server.js", "--api-key", FAKE_SECRETS[4], "--key2", FAKE_SECRETS[5]],
                    "env": {"DB_URL": "${DB_URL}"},
                }
            }
        },
    )
    _write_json(project / ".claude" / "settings.json", {"sandbox": {"enabled": True}})

    skill = home / ".claude" / "skills" / "pdf"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: pdf\n---\nDo PDF things.\n", encoding="utf-8")
    (skill / "extract.py").write_text("print('hi')\n", encoding="utf-8")

    agents = home / ".claude" / "agents"
    agents.mkdir(parents=True)
    (agents / "reviewer.md").write_text("---\nname: reviewer\n---\nReview code.\n", encoding="utf-8")

    commands = project / ".claude" / "commands"
    commands.mkdir(parents=True)
    (commands / "deploy.md").write_text("Deploy the app.\n", encoding="utf-8")

    (home / ".claude" / "plugins" / "cache" / "claude-plugins-official" / "code-review" / "1.2.0").mkdir(parents=True)

    _write_json(system / "managed-settings.json", {"allowManagedHooksOnly": True, "permissions": {"deny": ["Bash(sudo *)"]}})
    _write_json(system / "managed-mcp.json", {"mcpServers": {"company-docs": {"type": "http", "url": "https://docs.internal.example/mcp"}}})

    return ScanContext(home=home, project=project, env={}, system_dirs={"claude_code": system})
