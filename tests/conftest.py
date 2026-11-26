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
    # Week 3: other AI tools
    "ctx7-FAKE-secret-value-0001",
    "secretFAKE77",
    "corpFAKEkey",
    "vscodeFAKEsecret123",
    "codexFAKEenvvalue1",
    "figmaFAKEheader22",
    "geminiFAKEkey333",
    "geminiFAKEurl444",
    "geminiFAKEbearer555",
    "geminiExtFAKE666",
    "cursorFAKEbearer777",
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
                },
                # A project inside the home folder: its path must print as ~/code/site.
                str(home / "code" / "site"): {
                    "mcpServers": {
                        "playwright": {"command": "npx", "args": ["@playwright/mcp@latest"]}
                    }
                },
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

    system_dirs = _add_other_tools(home, project, tmp_path / "system")
    system_dirs["claude_code"] = system
    return ScanContext(home=home, project=project, platform_os="darwin", env={}, system_dirs=system_dirs)


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _add_other_tools(home: Path, project: Path, system_root: Path) -> dict[str, Path]:
    """Fake configs for Copilot, VS Code, Codex, Gemini CLI and Cursor."""
    # GitHub Copilot
    _write_json(
        home / ".copilot" / "mcp-config.json",
        {
            "mcpServers": {
                "playwright": {"type": "local", "command": "npx", "args": ["@playwright/mcp@latest"], "tools": ["*"]},
                "context7": {
                    "type": "http",
                    "url": "https://mcp.context7.com/mcp",
                    "headers": {"CONTEXT7_API_KEY": "ctx7-FAKE-secret-value-0001"},
                    "tools": ["*"],
                },
            }
        },
    )
    _write_json(
        home / ".copilot" / "hooks" / "audit.json",
        {"version": 1, "hooks": {"preToolUse": [{"type": "command", "bash": "./audit.sh --token secretFAKE77", "timeoutSec": 10}]}},
    )
    _write_json(
        project / ".github" / "hooks" / "policy.json",
        {"hooks": {"PreToolUse": [{"matcher": "shell", "hooks": [{"type": "command", "command": "python3 .github/hooks/check.py"}]}]}},
    )
    _write_json(project / ".github" / "copilot" / "settings.json", {"disableAllHooks": False})
    copilot_policy = system_root / "copilot-policy.d"
    _write_json(
        copilot_policy / "00-company.json",
        {"version": 1, "hooks": {"preToolUse": [{"type": "http", "url": "https://policy.corp.example/check", "headers": {"X-Key": "corpFAKEkey"}}]}},
    )

    # VS Code (macOS user profile path, JSON with comments and a trailing comma)
    _write_text(
        home / "Library" / "Application Support" / "Code" / "User" / "mcp.json",
        """{
  // Prompted values are never stored in this file
  "inputs": [{"id": "github-pat", "type": "promptString", "password": true}],
  "servers": {
    "github": {"type": "http", "url": "https://api.githubcopilot.com/mcp/",
               "headers": {"Authorization": "Bearer ${input:github-pat}"}},
    /* a local server */
    "fs": {"type": "stdio", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "~/docs"],
           "env": {"SECRET_THING": "vscodeFAKEsecret123"}},
  },
}
""",
    )
    _write_json(project / ".vscode" / "mcp.json", {"servers": {"local-db": {"command": "node", "args": ["db.js"]}}})

    # OpenAI Codex
    _write_text(
        home / ".codex" / "config.toml",
        """approval_policy = "never"
sandbox_mode = "danger-full-access"

[mcp_servers.context7]
command = "npx"
args = ["-y", "@upstash/context7-mcp"]
env_vars = ["LOCAL_TOKEN"]

[mcp_servers.context7.env]
MY_ENV_VAR = "codexFAKEenvvalue1"

[mcp_servers.figma]
url = "https://mcp.figma.com/mcp"
bearer_token_env_var = "FIGMA_OAUTH_TOKEN"
http_headers = { "X-Figma-Region" = "us-east-1", "X-Api-Key" = "figmaFAKEheader22" }
enabled_tools = ["open", "screenshot"]

[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "python3 ~/.codex/hooks/policy.py"
""",
    )
    _write_json(
        project / ".codex" / "hooks.json",
        {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "python3 init.py"}]}]}},
    )

    # Gemini CLI
    _write_text(
        home / ".gemini" / "settings.json",
        """{
  // user settings
  "general": {"defaultApprovalMode": "auto_edit"},
  "security": {"folderTrust": {"enabled": false}},
  "tools": {"allowed": ["run_shell_command(git)"]},
  "mcpServers": {
    "weather": {"command": "node", "args": ["w.js"], "env": {"WEATHER_KEY": "geminiFAKEkey333"},
                "trust": true, "excludeTools": ["delete"]},
    "remote": {"httpUrl": "https://mcp.example.com/mcp?token=geminiFAKEurl444",
               "headers": {"Authorization": "Bearer geminiFAKEbearer555"}}
  },
  "hooks": {"BeforeTool": [{"matcher": "write_file|replace", "hooks": [
    {"name": "secret-scanner", "type": "command", "command": "$GEMINI_PROJECT_DIR/.gemini/hooks/block-secrets.sh"}]}]}
}
""",
    )
    gemini_system = system_root / "GeminiCli"
    _write_json(gemini_system / "settings.json", {"security": {"disableYoloMode": True}})
    ext = home / ".gemini" / "extensions" / "gcp"
    _write_json(
        ext / "gemini-extension.json",
        {"name": "gcp", "version": "1.0.0", "mcpServers": {"gcp-tools": {"command": "node", "args": ["${extensionPath}/server.js"]}}},
    )
    _write_json(ext / "hooks" / "hooks.json", {"hooks": {"AfterTool": [{"hooks": [{"type": "command", "command": "./log.sh"}]}]}})
    _write_text(ext / ".env", "API_KEY=geminiExtFAKE666\n")

    # Cursor
    _write_json(
        home / ".cursor" / "mcp.json",
        {"mcpServers": {"linear": {"url": "https://mcp.linear.app/sse", "headers": {"Authorization": "Bearer cursorFAKEbearer777"}}}},
    )
    _write_json(
        project / ".cursor" / "mcp.json",
        {"mcpServers": {"local": {"command": "python", "args": ["${workspaceFolder}/tools/server.py"], "env": {"API_KEY": "${env:API_KEY}"}}}},
    )
    _write_json(
        home / ".cursor" / "hooks.json",
        {"version": 1, "hooks": {"beforeShellExecution": [{"command": "./guard.sh"}], "beforeMCPExecution": [{"command": "./mcp-log.sh"}]}},
    )
    cursor_enterprise = system_root / "Cursor"
    _write_json(cursor_enterprise / "hooks.json", {"version": 1, "hooks": {"beforeShellExecution": [{"command": "/opt/corp/guard"}]}})

    return {"copilot_policy": copilot_policy, "gemini_system": gemini_system, "cursor_enterprise": cursor_enterprise}
