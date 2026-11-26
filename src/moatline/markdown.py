"""A plain-language Markdown report, written for a non-technical reader.

Everything that came from a config file is escaped, because config files can
be written by other people (a cloned repo's .mcp.json). Without escaping, a
server name could add fake links, images or headings to a report someone
opens on GitHub.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import PurePath

from moatline import __version__
from moatline.checks import OWASP, RULES, counts_by_severity, run_checks
from moatline.discovery.base import ScanContext
from moatline.models import Asset, Finding, ScanResult
from moatline.report import (
    KIND_ORDER,
    PLATFORM_ORDER,
    PLATFORM_TITLES,
    FindingGroup,
    _clean,
    _describe,
    _printable,
    _shorten,
    clean_findings,
    group_findings,
)

SEVERITY_HEADINGS = {
    "high": "High: fix these first",
    "medium": "Medium: fix soon",
    "low": "Low: worth tidying up",
}
SEVERITY_MEANING = {
    "high": "could let an agent cause real damage or expose a key. Fix this week.",
    "medium": "makes an attack easier or harder to notice. Fix soon.",
    "low": "good security habit. Fix when convenient.",
}
KIND_PLAIN = {
    "mcp_server": "MCP servers (tools your agents can call)",
    "hook": "Hooks (scripts that run automatically)",
    "plugin": "Plugins",
    "marketplace": "Plugin marketplaces",
    "skill": "Skills",
    "subagent": "Subagents",
    "command": "Custom commands",
    "extension": "Extensions",
    "settings_file": "Settings files",
}
SCOPE_PLAIN = {
    "user": "all your projects",
    "project": "this project",
    "local": "this project, just you",
    "managed": "set by your organization",
    "plugin": "plugin",
    "extension": "extension",
}
NOT_CHECKED = [
    "Skills and subagents for AI tools other than Claude Code",
    "Codex settings managed by an organization",
    "Cursor's organization-wide settings on Windows",
    "Antigravity",
]

# Enough to stop emphasis, links, images, HTML and table breaks. "(" and "!"
# are harmless once "[" is escaped, so they stay readable.
_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|])")


def md(text: object) -> str:
    """Escape text from a config file so Markdown shows it as plain words."""
    return _MD_SPECIAL.sub(r"\\\1", _printable(str(text)).replace("\n", " "))


def code(text: object) -> str:
    """Show text from a config file as inline code, safe even if it holds backticks."""
    value = _printable(str(text)).replace("\n", " ")
    longest = max((len(run) for run in re.findall(r"`+", value)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if value.startswith("`") or value.endswith("`") or not value else ""
    return f"{fence}{pad}{value}{pad}{fence}"


def _cell(text: object) -> str:
    return md(text) if text != "" else " "


def _table_code(text: object) -> str:
    # Inside a table even code spans need "|" escaped, or the row splits.
    return code(text).replace("|", "\\|")


def _where(finding: Finding) -> str:
    tool = PLATFORM_TITLES.get(finding.platform, finding.platform)
    if finding.asset == PurePath(finding.source.replace("\\", "/")).name:
        return f"{tool}, {code(finding.source)}"
    return f"{tool}, {code(finding.asset)} in {code(finding.source)}"


def _date(now: datetime) -> str:
    return f"{now:%B} {now.day}, {now.year}"


def _group_lines(number: int, group: FindingGroup) -> list[str]:
    f = group.first
    lines = [f"#### {number}. {md(group.title)}", ""]
    if len(group.items) == 1:
        lines.append(f"- **Where:** {_where(f)}")
        if f.evidence:
            lines.append(f"- **Found:** {code(f.evidence)}")
    else:
        lines.append("- **Where:**")
        for item in group.items:
            lines.append(f"  - {_where(item)}" + (f": {code(item.evidence)}" if item.evidence else ""))
    lines.append(f"- **Why it matters:** {md(f.why)}")
    lines.append(f"- **How to fix:** {md(f.fix)}")
    lines.append(f"- **Risk type:** OWASP {md(f.owasp)} (check {f.check_id})")
    lines.append("")
    return lines


def _summary_lines(result: ScanResult, findings: list[Finding]) -> list[str]:
    counts = result.count_by_kind()
    risk = counts_by_severity(findings)
    tools = [PLATFORM_TITLES[p] for p in PLATFORM_ORDER if any(a.platform == p for a in result.assets)]
    lines = ["## At a glance", "", "| | |", "|---|---|"]
    lines.append(f"| AI tools found | {md(', '.join(tools)) if tools else 'None'} |")
    for kind in KIND_ORDER:
        if kind in counts:
            lines.append(f"| {KIND_PLAIN[kind]} | {counts[kind]} |")
    lines.append(f"| **Risks found** | **{risk['high']} high, {risk['medium']} medium, {risk['low']} low** |")
    lines.append("")
    return lines


def _top_fixes(groups: list[FindingGroup]) -> list[str]:
    lines = ["## Start here: your top 3 fixes", ""]
    if not groups:
        return lines + ["No risky settings found. Nice work.", ""]
    for number, group in enumerate(groups[:3], start=1):
        f = group.first
        lines.append(f"{number}. **{f.severity.capitalize()}: {md(group.title)}.** {md(f.fix)}")
    lines.append("")
    return lines


def _inventory_lines(result: ScanResult, ctx: ScanContext) -> list[str]:
    lines = ["## What's installed", ""]
    if not result.assets:
        return lines + ["No AI-agent configuration was found.", ""]
    found = {a.platform for a in result.assets}
    for platform in [p for p in PLATFORM_ORDER if p in found] + sorted(found - set(PLATFORM_ORDER)):
        lines += [f"### {md(PLATFORM_TITLES.get(platform, platform))}", ""]
        lines += ["| Type | Name | Applies to | Details | File |", "|---|---|---|---|---|"]
        for kind in KIND_ORDER:
            for asset in (a for a in result.assets if a.platform == platform and a.kind == kind):
                cleaned = Asset(asset.kind, asset.platform, asset.scope, asset.name, asset.source, _clean(asset.details, ctx.home))
                lines.append(
                    f"| {KIND_PLAIN[kind].split(' (')[0]} | {_table_code(asset.name)} | {SCOPE_PLAIN.get(asset.scope, md(asset.scope))}"
                    f" | {_cell(_describe(cleaned))} | {_table_code(_shorten(asset.source, ctx.home))} |"
                )
        lines.append("")
    return lines


def _about_lines(result: ScanResult, ctx: ScanContext) -> list[str]:
    lines = ["## About this report", "", "**What the levels mean**", ""]
    for severity, meaning in SEVERITY_MEANING.items():
        lines.append(f"- **{severity.capitalize()}:** {meaning}")
    lines += ["", "**What this scan checks**", ""]
    for check_id, rule in RULES.items():
        lines.append(f"- {check_id}: {rule.summary} ({OWASP[rule.owasp]})")
    lines += ["", "**Not checked yet**", ""]
    lines += [f"- {item}" for item in NOT_CHECKED]
    if result.errors:
        lines += ["", "**Files that couldn't be read**", ""]
        for error in result.errors:
            lines.append(f"- {code(_shorten(error.source, ctx.home))}: {md(error.reason)}")
    lines += [
        "",
        "**How the scan works**",
        "",
        "- It only reads files. Nothing on this computer was changed.",
        "- It never connects to the internet. Nothing was sent anywhere.",
        "- Secret values are never shown. Only their names appear, plus the last 4 characters of long keys so you know which one to replace.",
        "- Risk types follow the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/).",
        "",
    ]
    return lines


def to_markdown(
    result: ScanResult,
    ctx: ScanContext,
    findings: list[Finding] | None = None,
    now: datetime | None = None,
) -> str:
    if findings is None:
        findings = run_checks(result, ctx)
    now = now or datetime.now().astimezone()
    groups = group_findings(clean_findings(findings, ctx))

    lines = [
        "# Moatline AI agent security report",
        "",
        f"**Scanned:** {_date(now)} · **Moatline:** v{__version__} · **Project folder:** {code(_shorten(str(ctx.project), ctx.home))}",
        "",
        "This report lists the AI agents set up on this computer, what they can reach, and the settings that put you at risk.",
        "",
    ]
    lines += _summary_lines(result, findings)
    lines += _top_fixes(groups)
    if groups:
        lines += ["## All findings", ""]
        number = 0
        for severity, heading in SEVERITY_HEADINGS.items():
            in_level = [g for g in groups if g.first.severity == severity]
            if not in_level:
                continue
            lines += [f"### {heading}", ""]
            for group in in_level:
                number += 1
                lines += _group_lines(number, group)
    lines += _inventory_lines(result, ctx)
    lines += _about_lines(result, ctx)
    return "\n".join(_printable(line) for line in lines).rstrip() + "\n"
