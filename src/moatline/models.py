"""Data types for what the scanner finds."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Asset:
    """One thing an AI agent can use or that changes how it behaves.

    kind: settings_file, mcp_server, hook, plugin, skill, subagent, command,
          marketplace
    platform: the AI tool, for example "claude_code"
    scope: managed, user, project, local, or plugin
    name: a short label for people
    source: the file or folder it was found in
    details: extra facts, already passed through redaction
    """

    kind: str
    platform: str
    scope: str
    name: str
    source: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ScanError:
    """A file the scanner could not read or understand."""

    platform: str
    source: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass(frozen=True)
class Finding:
    """A risk found in the scanned configuration, explained in plain language.

    check_id: stable ID such as "ML001", so findings can be tracked over time
    severity: high, medium or low
    title: one short line a non-expert understands
    why: one sentence on why it matters
    fix: one sentence on what to do
    owasp: the matching OWASP Top 10 for Agentic Applications risk
    evidence: the exact setting, already redacted
    """

    check_id: str
    severity: str
    title: str
    platform: str
    scope: str
    asset: str
    source: str
    why: str
    fix: str
    owasp: str
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    assets: list[Asset] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)
    scanned_files: list[str] = field(default_factory=list)

    def extend(self, other: "ScanResult") -> None:
        self.assets.extend(other.assets)
        self.errors.extend(other.errors)
        self.scanned_files.extend(other.scanned_files)

    def count_by_kind(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for asset in self.assets:
            counts[asset.kind] = counts.get(asset.kind, 0) + 1
        return dict(sorted(counts.items()))
