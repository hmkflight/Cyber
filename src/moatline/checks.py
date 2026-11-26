"""Risk checks: turn discovered configuration into plain-language findings.

Checks only look at the assets discovery already produced (and redacted).
They never open files themselves, so they can't reveal anything discovery
didn't already make safe.

Every finding maps to the OWASP Top 10 for Agentic Applications (2026).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Callable, Iterable

from moatline.discovery.base import ScanContext
from moatline.models import SEVERITY_ORDER, Asset, Finding, ScanError, ScanResult
from moatline.redact import REDACTED, looks_secret_name

OWASP = {
    "ASI02": "ASI02 Tool Misuse and Exploitation",
    "ASI03": "ASI03 Identity and Privilege Abuse",
    "ASI04": "ASI04 Agentic Supply Chain Vulnerabilities",
    "ASI05": "ASI05 Unexpected Code Execution",
    "ASI07": "ASI07 Insecure Inter-Agent Communication",
}

TOOL_NAMES = {
    "claude_code": "Claude Code",
    "copilot": "GitHub Copilot",
    "vscode": "VS Code",
    "codex": "OpenAI Codex",
    "gemini_cli": "Gemini CLI",
    "cursor": "Cursor",
}

# Claude Code marketplace names reserved for Anthropic's own repositories.
# Community marketplaces are not listed: their plugins are written by third parties.
OFFICIAL_MARKETPLACES = {
    "claude-plugins-official", "claude-code-marketplace", "claude-code-plugins", "anthropic-marketplace",
    "anthropic-plugins", "agent-skills", "anthropic-agent-skills", "life-sciences", "knowledge-work-plugins",
    "claude-for-legal", "claude-for-financial-services", "financial-services-plugins", "first-party-plugins",
    "claude-tag-plugins",
}

# Words in a server's name, URL or command that suggest it can move money,
# send messages, or change data and infrastructure.
_HIGH_IMPACT = re.compile(
    r"(?<![a-z])(trading|robinhood|broker|bank|payment|stripe|paypal|plaid|wallet|crypto|coinbase|gmail|email"
    r"|mail|slack|database|postgres|mysql|mongodb|supabase|aws|azure|gcloud|kubernetes)"
)

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "[::1]"}


def _tool(asset: Asset) -> str:
    return TOOL_NAMES.get(asset.platform, asset.platform)


def _finding(
    check_id: str, severity: str, title: str, asset: Asset, why: str, fix: str, owasp: str, evidence: str = ""
) -> Finding:
    return Finding(
        check_id=check_id,
        severity=severity,
        title=title,
        platform=asset.platform,
        scope=asset.scope,
        asset=asset.name,
        source=asset.source,
        why=why,
        fix=fix,
        owasp=OWASP[owasp],
        evidence=evidence[:200],
    )


def _of_kind(result: ScanResult, kind: str) -> Iterable[Asset]:
    return (a for a in result.assets if a.kind == kind)


# ML001 Auto-updating package ---------------------------------------------------

_DOCKER_VALUE_FLAGS = {
    "-e", "--env", "-v", "--volume", "-p", "--publish", "--name", "--network", "-w", "--workdir",
    "--entrypoint", "--env-file", "-u", "--user", "--mount", "--platform", "-l", "--label",
}
_EXACT_NPM_VERSION = re.compile(r"^\d+\.\d+\.\d+([-+].*)?$")


def _first_positional(args: list[str], value_flags: set[str] | frozenset[str] = frozenset()) -> str | None:
    skip = False
    for arg in args:
        if skip:
            skip = False
        elif arg in value_flags:
            skip = True
        elif not arg.startswith("-"):
            return arg
    return None


def _flag_value(args: list[str], *flags: str) -> str | None:
    for flag in flags:
        if flag in args:
            index = args.index(flag)
            return args[index + 1] if index + 1 < len(args) else None
    return None


def _is_local(spec: str) -> bool:
    return spec.startswith((".", "/", "~", "$", "\\")) or "\\" in spec or spec.endswith((".py", ".js", ".ts", ".mjs"))


def _npm_unpinned(spec: str) -> bool:
    body = spec[1:] if spec.startswith("@") else spec  # "@scope/name@1.2.3" -> "scope/name@1.2.3"
    if "@" not in body:
        return True
    version = body.rsplit("@", 1)[1]
    return not _EXACT_NPM_VERSION.match(version)


def _python_unpinned(spec: str) -> bool:
    return "==" not in spec and not re.search(r"@v?\d", spec)


def unpinned_package(command: str, args: list[str]) -> str | None:
    """Return the package if this command downloads a not-exactly-pinned package each run."""
    name = Path(command.replace("\\", "/")).name.lower()
    for suffix in (".cmd", ".exe"):
        name = name.removesuffix(suffix)

    if name in {"npx", "bunx", "pnpx"} or (name in {"pnpm", "bun", "yarn"} and args[:1] == ["dlx"]):
        rest = args[1:] if args[:1] == ["dlx"] else args
        spec = _flag_value(rest, "-p", "--package") or _first_positional(rest)
        return spec if spec and not _is_local(spec) and _npm_unpinned(spec) else None

    python_rest = None
    if name == "uvx":
        python_rest = args
    elif name == "pipx" and args[:1] == ["run"]:
        python_rest = args[1:]
    elif name == "uv" and args[:2] == ["tool", "run"]:
        python_rest = args[2:]
    if python_rest is not None:
        spec = _flag_value(python_rest, "--from", "--spec") or _first_positional(python_rest, {"--python", "--with"})
        return spec if spec and not _is_local(spec) and _python_unpinned(spec) else None

    if name in {"docker", "podman"} and args[:1] == ["run"]:
        image = _first_positional(args[1:], _DOCKER_VALUE_FLAGS)
        if image and "@sha256:" not in image:
            last = image.rsplit("/", 1)[-1]
            if ":" not in last or last.endswith(":latest"):
                return image
    return None


def check_unpinned_packages(result: ScanResult, ctx: ScanContext) -> list[Finding]:
    findings = []
    for asset in _of_kind(result, "mcp_server"):
        command = asset.details.get("command")
        if not command:
            continue
        spec = unpinned_package(command, [str(a) for a in asset.details.get("args", [])])
        if spec:
            findings.append(_finding(
                "ML001", "medium", f"'{asset.name}' downloads its newest version every time it starts", asset,
                "A new release, or a hijacked one, runs on your machine automatically without anyone checking it first.",
                "Pin an exact version (for example name@1.2.3) and update on purpose after reviewing what changed.",
                "ASI04", f"{command} {spec}",
            ))
    return findings


# ML002 Acts without asking -----------------------------------------------------

_BROAD_SHELL_RULES = {"Bash", "Bash(*)", "Bash(*:*)", "Bash(**)"}


def check_acts_without_asking(result: ScanResult, ctx: ScanContext) -> list[Finding]:
    findings = []
    for asset in _of_kind(result, "settings_file"):
        d = asset.details
        if d.get("default_permission_mode") == "bypassPermissions":
            findings.append(_finding(
                "ML002", "high", "Claude Code is set to act without asking you", asset,
                "Every file edit and shell command runs with no approval step, so one bad instruction can do real damage.",
                "Remove \"defaultMode\": \"bypassPermissions\" and add allow rules only for the commands you trust.",
                "ASI02", "defaultMode: bypassPermissions",
            ))
        broad = sorted(str(r) for r in d.get("allow_rules", []) if r in _BROAD_SHELL_RULES)
        if broad:
            findings.append(_finding(
                "ML002", "medium", "Claude Code may run any shell command without asking", asset,
                "An allow rule this wide lets every command through, including ones that delete files or send data out.",
                "Replace it with rules for specific commands, such as Bash(npm run test *).",
                "ASI02", "allow: " + ", ".join(broad),
            ))
        if d.get("approval_policy") == "never":
            findings.append(_finding(
                "ML002", "high", "Codex never asks before running commands", asset,
                "Codex can run commands and change files with no approval step.",
                "Set approval_policy to \"on-request\" or \"untrusted\" in config.toml.",
                "ASI02", "approval_policy = never",
            ))
        if d.get("default_approval_mode") in ("auto_edit", "yolo"):
            yolo = d["default_approval_mode"] == "yolo"
            findings.append(_finding(
                "ML002", "high" if yolo else "low",
                "Gemini CLI runs every tool without asking" if yolo else "Gemini CLI edits files without asking",
                asset,
                "Tool calls run with no approval step." if yolo else "File changes are applied without a review step.",
                "Set general.defaultApprovalMode to \"default\".",
                "ASI02", f"defaultApprovalMode: {d['default_approval_mode']}",
            ))
    for asset in _of_kind(result, "mcp_server"):
        if asset.details.get("trust") is True:
            findings.append(_finding(
                "ML002", "medium", f"{_tool(asset)} runs every tool from '{asset.name}' without asking", asset,
                "Marking a server as trusted skips the confirmation step for everything it can do.",
                "Remove \"trust\": true, or limit the server to read-only tools with includeTools.",
                "ASI02", "trust: true",
            ))
    return findings


# ML003 No sandbox --------------------------------------------------------------


def check_sandbox(result: ScanResult, ctx: ScanContext) -> list[Finding]:
    findings = []
    claude_settings = []
    for asset in _of_kind(result, "settings_file"):
        d = asset.details
        if d.get("sandbox_mode") == "danger-full-access":
            findings.append(_finding(
                "ML003", "high", "Codex runs with no sandbox", asset,
                "Commands Codex runs can read and change anything your account can, including other projects and keys.",
                "Set sandbox_mode to \"workspace-write\" in config.toml.",
                "ASI05", "sandbox_mode = danger-full-access",
            ))
        if d.get("folder_trust") is False:
            findings.append(_finding(
                "ML003", "low", "Gemini CLI trusts every folder", asset,
                "Settings and hooks inside any project you open can take effect without you approving that folder.",
                "Turn security.folderTrust.enabled back on.",
                "ASI05", "folderTrust.enabled: false",
            ))
        if asset.platform == "claude_code":
            claude_settings.append(asset)

    uses_claude = any(a.platform == "claude_code" and a.kind in ("mcp_server", "hook", "plugin") for a in result.assets)
    if (claude_settings or uses_claude) and not any(a.details.get("sandbox_enabled") is True for a in claude_settings):
        where = next((a for a in claude_settings if a.scope == "user"), None) or Asset(
            "settings_file", "claude_code", "user", "settings.json", str(ctx.home / ".claude" / "settings.json"), {}
        )
        findings.append(_finding(
            "ML003", "low", "Claude Code's sandbox is not turned on", where,
            "Without the sandbox, shell commands Claude runs can reach any file and any website your account can.",
            "Run /sandbox in Claude Code, or add \"sandbox\": {\"enabled\": true} to ~/.claude/settings.json.",
            "ASI05", "sandbox.enabled is not set in any Claude Code settings file",
        ))
    return findings


# ML004 / ML005 Secrets ---------------------------------------------------------


def check_secrets(result: ScanResult, ctx: ScanContext) -> list[Finding]:
    findings = []
    for asset in result.assets:
        names = [str(n) for n in asset.details.get("literal_secret_names") or []]
        in_url = asset.details.get("url_has_secret") is True
        if names or in_url:
            where = {
                "mcp_server": f"the '{asset.name}' server settings",
                "hook": f"the '{asset.name}' hook",
            }.get(asset.kind, Path(asset.source).name)
            found = (["names: " + ", ".join(names)] if names else []) + (["a key or password inside its URL"] if in_url else [])
            findings.append(_finding(
                "ML004", "high", f"Secret typed directly into {where}", asset,
                "Anything that can read this file, including AI agents, backups and synced folders, can read the key.",
                "Move the value into an environment variable or your keychain, reference it as ${NAME}, then rotate the key.",
                "ASI03", "; ".join(found),
            ))
        if asset.kind not in ("mcp_server", "hook"):
            continue
        line = " ".join(str(p) for p in [asset.details.get("command") or "", *asset.details.get("args", [])]).strip()
        if REDACTED in line:
            findings.append(_finding(
                "ML005", "high", f"Secret written into the command line for '{asset.name}'", asset,
                "Command lines show up in process lists and logs, where other programs on the machine can read them.",
                "Pass the secret through an environment variable instead of a command-line argument, then rotate it.",
                "ASI03", line,
            ))
    return findings


# ML006 Powerful tool reachable broadly -----------------------------------------


def _is_high_impact(asset: Asset) -> bool:
    d = asset.details
    text = " ".join([asset.name, str(d.get("url", "")), str(d.get("command", "")), *map(str, d.get("args", []))])
    return bool(_HIGH_IMPACT.search(text.lower()))


def _norm_path(path: str) -> str:
    return path.replace("\\", "/").rstrip("/").casefold()


def check_reach(result: ScanResult, ctx: ScanContext) -> list[Finding]:
    findings = []
    home = _norm_path(str(ctx.home))
    for asset in _of_kind(result, "mcp_server"):
        high_impact = _is_high_impact(asset)
        project_path = _norm_path(str(asset.details.get("project_path") or ""))
        if project_path and project_path == home:
            findings.append(_finding(
                "ML006", "high" if high_impact else "medium",
                f"'{asset.name}' is switched on for your whole home folder", asset,
                "Agents started from your home folder can use it, which is far more often than one project needs"
                + (", and it can act on money, messages or data." if high_impact else "."),
                "Remove it from the home-folder entry and add it only to the project folder that needs it.",
                "ASI03", "registered for project folder ~",
            ))
        elif high_impact and asset.scope == "user":
            findings.append(_finding(
                "ML006", "low", f"Powerful tool '{asset.name}' is available in every project", asset,
                "A tool that can move money, send messages or change data is within reach of every agent session.",
                "Limit it to the projects that need it, or allow only its read-only tools.",
                "ASI03", str(asset.details.get("url") or asset.details.get("command") or ""),
            ))
    return findings


# ML007 Project hooks -----------------------------------------------------------


def check_project_hooks(result: ScanResult, ctx: ScanContext) -> list[Finding]:
    findings = []
    for asset in _of_kind(result, "hook"):
        if asset.scope != "project":
            continue
        action = asset.details.get("command") or asset.details.get("url") or asset.details.get("prompt_preview") or ""
        findings.append(_finding(
            "ML007", "medium", f"This project runs a {_tool(asset)} hook automatically", asset,
            "Whoever can change this project, such as a teammate or the author of a cloned repo, decides what runs on your computer.",
            "Read the hook and its script before trusting the folder, and review changes to it like code.",
            "ASI05", f"{asset.details.get('event', '')}: {action}",
        ))
    return findings


# ML008 Plain http --------------------------------------------------------------


def _host(url: str) -> str:
    authority = url.split("://", 1)[1].split("/", 1)[0].split("?", 1)[0].split("@")[-1].lower()
    if authority.startswith("["):
        return authority.split("]", 1)[0] + "]"
    return authority.split(":", 1)[0]


def check_plain_http(result: ScanResult, ctx: ScanContext) -> list[Finding]:
    findings = []
    for asset in result.assets:
        if asset.kind not in ("mcp_server", "hook"):
            continue
        url = str(asset.details.get("url") or "")
        if not url.lower().startswith("http://") or _host(url) in _LOCAL_HOSTS:
            continue
        findings.append(_finding(
            "ML008", "medium", f"'{asset.name}' talks to a remote server without encryption", asset,
            "Plain http lets anyone on the same network read or change what the agent sends and receives.",
            "Switch to the server's https:// address.",
            "ASI07", url,
        ))
    return findings


# ML009 Third-party plugins and extensions --------------------------------------


def check_third_party_extensions(result: ScanResult, ctx: ScanContext) -> list[Finding]:
    findings = []
    for asset in _of_kind(result, "plugin"):
        marketplace = str(asset.details.get("marketplace", ""))
        if marketplace in OFFICIAL_MARKETPLACES:
            continue
        findings.append(_finding(
            "ML009", "low", f"Plugin '{asset.name}' comes from a third-party marketplace", asset,
            "Plugins run with your full user permissions, and their files can change whenever they update.",
            "Check who publishes it and look at its hooks and MCP servers before keeping it.",
            "ASI04", f"marketplace: {marketplace}",
        ))
    for asset in _of_kind(result, "extension"):
        d = asset.details
        findings.append(_finding(
            "ML009", "low", f"{_tool(asset)} extension '{asset.name}' is installed", asset,
            "Extensions can add tools and hooks that run with your user permissions.",
            "Check who publishes it and look at what it adds before keeping it.",
            "ASI04", f"adds {d.get('mcp_server_count', 0)} MCP server(s) and {d.get('hook_count', 0)} hook(s)",
        ))
    return findings


# ML010 One key shared by several AI tools ---------------------------------------


def _credential_names(asset: Asset) -> set[str]:
    d = asset.details
    names = {str(n) for n in [*d.get("env_names", []), *d.get("header_names", [])] if looks_secret_name(n)}
    if d.get("token_env_var"):
        names.add(str(d["token_env_var"]))
    return names


def check_shared_credentials(result: ScanResult, ctx: ScanContext) -> list[Finding]:
    users: dict[str, list[Asset]] = {}
    for asset in _of_kind(result, "mcp_server"):
        for name in _credential_names(asset):
            users.setdefault(name, []).append(asset)
    findings = []
    for name, assets in sorted(users.items()):
        tools = sorted({_tool(a) for a in assets})
        if len(tools) < 2 or name.lower() == "authorization":
            continue  # "Authorization" is a header name, not one specific key
        findings.append(_finding(
            "ML010", "low", f"{name} is shared by {len(tools)} AI tools", assets[0],
            "If any one of these agents is tricked into leaking or misusing the key, all of them are exposed, and you can't tell which one did it.",
            "Give each AI tool its own key with only the access it needs, so you can revoke one without breaking the others.",
            "ASI03", "used by " + ", ".join(f"{_tool(a)} '{a.name}'" for a in assets),
        ))
    return findings


CHECKS: list[Callable[[ScanResult, ScanContext], list[Finding]]] = [
    check_acts_without_asking,
    check_sandbox,
    check_secrets,
    check_reach,
    check_unpinned_packages,
    check_project_hooks,
    check_plain_http,
    check_third_party_extensions,
    check_shared_credentials,
]


def run_checks(result: ScanResult, ctx: ScanContext) -> list[Finding]:
    """Run every check. A bug in one check is reported as an error and never hides the others."""
    findings: list[Finding] = []
    for check in CHECKS:
        try:
            findings.extend(check(result, ctx))
        except Exception as exc:  # noqa: BLE001 - rule 5: never crash
            error = ScanError("moatline", f"risk check {check.__name__}", f"check failed ({type(exc).__name__})")
            if error not in result.errors:
                result.errors.append(error)
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.check_id, f.platform, f.asset))


def counts_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts
