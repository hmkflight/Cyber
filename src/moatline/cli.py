"""Command-line entry point: ``moatline scan``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from moatline import __version__
from moatline.discovery import DISCOVERERS, run_all
from moatline.discovery.base import ScanContext
from moatline.report import to_json, to_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="moatline",
        description="Read-only inventory of AI-agent configurations on this machine.",
    )
    parser.add_argument("--version", action="version", version=f"moatline {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="find agent configs, MCP servers, hooks, plugins and skills")
    scan.add_argument("--project", type=Path, default=None, help="project folder to scan (default: current folder)")
    scan.add_argument("--format", choices=["text", "json"], default="text", help="output format (default: text)")
    scan.add_argument(
        "--platform",
        action="append",
        choices=sorted(DISCOVERERS),
        help="only scan this AI tool (repeatable; default: all)",
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
    output = to_json(result, ctx) if args.format == "json" else to_text(result, ctx)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
