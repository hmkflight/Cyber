"""Command-line entry point: ``moatline scan``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from moatline import __version__
from moatline.checks import run_checks
from moatline.discovery import DISCOVERERS, run_all
from moatline.discovery.base import ScanContext
from moatline.markdown import to_markdown
from moatline.models import SEVERITY_ORDER
from moatline.report import to_json, to_text
from moatline.sarif import to_sarif

FORMATS = {
    "text": to_text,
    "json": to_json,
    "markdown": to_markdown,
    "sarif": to_sarif,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="moatline",
        description="Read-only inventory of AI-agent configurations on this machine.",
    )
    parser.add_argument("--version", action="version", version=f"moatline {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="find agent configs, MCP servers, hooks, plugins and skills")
    scan.add_argument("--project", type=Path, default=None, help="project folder to scan (default: current folder)")
    scan.add_argument(
        "--format",
        choices=list(FORMATS),
        default="text",
        help="text (default), json, markdown (a report to share) or sarif (for GitHub's security tab)",
    )
    scan.add_argument(
        "--output",
        type=Path,
        default=None,
        help="save the report to this new file instead of printing it (never overwrites an existing file)",
    )
    scan.add_argument(
        "--platform",
        action="append",
        choices=sorted(DISCOVERERS),
        help="only scan this AI tool (repeatable; default: all)",
    )
    scan.add_argument(
        "--fail-on",
        choices=list(SEVERITY_ORDER),
        default=None,
        help="exit with code 1 if any finding is this severe or worse (for CI)",
    )
    scan.add_argument("--home", type=Path, default=None, help=argparse.SUPPRESS)  # for tests and demos
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 0

    ctx = ScanContext.from_environment(project=args.project, home=args.home)
    if not ctx.project.is_dir():
        print(f"moatline: project folder not found: {ctx.project}", file=sys.stderr)
        return 2

    result = run_all(ctx, platforms=args.platform)
    findings = run_checks(result, ctx)
    output = FORMATS[args.format](result, ctx, findings)
    if args.output is None:
        print(output)
    elif not save_new_file(args.output, output):
        return 2
    if args.fail_on is not None:
        limit = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER.get(f.severity, 9) <= limit for f in findings):
            return 1
    return 0


def save_new_file(path: Path, text: str) -> bool:
    """Write the report to a file that doesn't exist yet. Never overwrites anything."""
    try:
        # "x" mode fails if the path already exists, including as a link.
        with open(path, "x", encoding="utf-8", newline="\n") as handle:
            handle.write(text.rstrip("\n") + "\n")
    except FileExistsError:
        print(f"moatline: {path} already exists. Choose a new file name; Moatline never overwrites files.", file=sys.stderr)
        return False
    except OSError as exc:
        print(f"moatline: could not save the report to {path} ({exc.strerror or 'error'})", file=sys.stderr)
        return False
    print(f"Report saved to {path}", file=sys.stderr)
    return True


if __name__ == "__main__":
    raise SystemExit(main())
