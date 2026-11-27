"""SARIF 2.1.0 output, the format GitHub's code scanning (security tab) reads.

Files inside the project folder get repo-relative paths, so GitHub can link
to them. Files elsewhere (the home folder) are shown as ~/... so the report
never reveals the username.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

from moatline import __version__
from moatline.checks import OWASP, RULES, run_checks
from moatline.discovery.base import ScanContext
from moatline.models import Finding, ScanResult
from moatline.report import _shorten

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"high": "error", "medium": "warning", "low": "note"}
# GitHub reads "security-severity" as a 0-10 score: 7+ high, 4-6.9 medium, below 4 low.
SECURITY_SEVERITY = {"high": "8.0", "medium": "5.5", "low": "3.0"}
INFORMATION_URI = "https://github.com/hmkflight/cyber"


def _location(source: str, ctx: ScanContext) -> dict[str, Any]:
    path = Path(source)
    try:
        relative = path.relative_to(ctx.project).as_posix()
        artifact = {"uri": quote(relative, safe="/~._-"), "uriBaseId": "%SRCROOT%"}
    except ValueError:
        shown = _shorten(source, ctx.home).replace("\\", "/")
        artifact = {"uri": quote(shown, safe="/~._-:")}
    return {"physicalLocation": {"artifactLocation": artifact, "region": {"startLine": 1}}}


def _fingerprint(f: Finding, ctx: ScanContext) -> str:
    """Stable across runs and machines, so GitHub can tell a finding is the same one."""
    key = "|".join([f.check_id, f.platform, f.scope, f.asset, _shorten(f.source, ctx.home), f.title])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def _rules() -> list[dict[str, Any]]:
    rules = []
    for check_id, rule in RULES.items():
        rules.append({
            "id": check_id,
            "name": rule.name,
            "shortDescription": {"text": rule.summary},
            "fullDescription": {"text": f"{rule.summary} OWASP Top 10 for Agentic Applications: {OWASP[rule.owasp]}."},
            "help": {"text": f"{rule.summary} The finding message says why it matters and how to fix it."},
            "defaultConfiguration": {"level": LEVEL[rule.worst]},
            "properties": {
                "tags": ["security", "ai-agents", f"owasp-agentic-{rule.owasp.lower()}"],
                "security-severity": SECURITY_SEVERITY[rule.worst],
            },
        })
    return rules


def _result(f: Finding, ctx: ScanContext, rule_index: dict[str, int]) -> dict[str, Any]:
    message = f"{f.title}. {f.why} How to fix: {f.fix}"
    if f.evidence:
        message += f" Found: {f.evidence}"
    return {
        "ruleId": f.check_id,
        "ruleIndex": rule_index[f.check_id],
        "level": LEVEL.get(f.severity, "note"),
        "message": {"text": _shorten(message, ctx.home)},
        "locations": [_location(f.source, ctx)],
        "partialFingerprints": {"moatlineFinding/v1": _fingerprint(f, ctx)},
        "properties": {
            "severity": f.severity,
            "tool": f.platform,
            "scope": f.scope,
            "item": f.asset,
            "owasp": f.owasp,
        },
    }


def to_sarif(result: ScanResult, ctx: ScanContext, findings: list[Finding] | None = None) -> str:
    if findings is None:
        findings = run_checks(result, ctx)
    rule_index = {check_id: i for i, check_id in enumerate(RULES)}
    notifications = [
        {"level": "warning", "message": {"text": f"{_shorten(e.source, ctx.home)}: {e.reason}"}}
        for e in result.errors
    ]
    run = {
        "tool": {
            "driver": {
                "name": "Moatline",
                "semanticVersion": __version__,
                "version": __version__,
                "informationUri": INFORMATION_URI,
                "rules": _rules(),
            }
        },
        "automationDetails": {"id": "moatline-agent-scan/"},
        "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": notifications}],
        "results": [_result(f, ctx, rule_index) for f in findings if f.check_id in rule_index],
    }
    return json.dumps({"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}, indent=2)
