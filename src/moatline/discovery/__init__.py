"""Discovery modules, one per AI tool.

To add a tool, write a module with a ``PLATFORM`` name and a
``scan(ctx: ScanContext) -> ScanResult`` function, then add it to DISCOVERERS.
"""

from __future__ import annotations

from moatline.discovery import claude_code
from moatline.discovery.base import ScanContext
from moatline.models import ScanError, ScanResult

DISCOVERERS = {
    claude_code.PLATFORM: claude_code.scan,
}


def run_all(ctx: ScanContext, platforms: list[str] | None = None) -> ScanResult:
    combined = ScanResult()
    for name, scan in DISCOVERERS.items():
        if platforms and name not in platforms:
            continue
        try:
            combined.extend(scan(ctx))
        except Exception as exc:  # a bug in one module must not stop the scan
            combined.errors.append(ScanError(name, "(scanner)", f"internal error: {type(exc).__name__}"))
    return combined
