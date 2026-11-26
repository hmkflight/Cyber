"""Shared helpers for discovery modules.

Every path the scanner reads comes from a ScanContext, so tests can point it at
fake folders and never touch the real home directory.
"""

from __future__ import annotations

import json
import os
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from moatline.models import ScanError, ScanResult

MAX_FILE_BYTES = 20 * 1024 * 1024  # skip anything bigger than 20 MB


@dataclass(frozen=True)
class ScanContext:
    home: Path
    project: Path
    platform_os: str = field(default_factory=lambda: sys.platform)
    env: dict[str, str] = field(default_factory=dict)
    # When set, replaces the operating system's managed-settings folders.
    system_dirs: dict[str, Path] | None = None

    @classmethod
    def from_environment(cls, project: Path | None = None, home: Path | None = None) -> "ScanContext":
        return cls(
            home=(home or Path.home()).expanduser().resolve(),
            project=(project or Path.cwd()).expanduser().resolve(),
            env=dict(os.environ),
        )


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas, leaving strings alone.

    VS Code and some other tools accept "JSON with comments" in their config
    files, so the scanner must too.
    """
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
        else:
            out.append(ch)
            i += 1
    cleaned = "".join(out)
    # Drop commas that sit right before a closing bracket (outside strings).
    result: list[str] = []
    in_string = False
    i = 0
    while i < len(cleaned):
        ch = cleaned[i]
        if in_string:
            result.append(ch)
            if ch == "\\" and i + 1 < len(cleaned):
                result.append(cleaned[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
            result.append(ch)
        elif ch == ",":
            j = i + 1
            while j < len(cleaned) and cleaned[j] in " \t\r\n":
                j += 1
            if j < len(cleaned) and cleaned[j] in "}]":
                i += 1
                continue
            result.append(ch)
        else:
            result.append(ch)
        i += 1
    return "".join(result)


def _read_text(path: Path, platform: str, result: ScanResult) -> str | None:
    if not path.is_file():
        return None
    result.scanned_files.append(str(path))
    try:
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            result.errors.append(ScanError(platform, str(path), f"skipped: file is larger than {MAX_FILE_BYTES} bytes"))
            return None
        with path.open("r", encoding="utf-8") as handle:
            return handle.read()
    except UnicodeDecodeError:
        result.errors.append(ScanError(platform, str(path), "not valid UTF-8 text"))
    except OSError as exc:
        result.errors.append(ScanError(platform, str(path), f"could not read: {exc.strerror or type(exc).__name__}"))
    return None


def read_json(path: Path, platform: str, result: ScanResult, allow_comments: bool = False) -> Any | None:
    """Read a JSON file for reading only. Problems become ScanErrors, never exceptions."""
    text = _read_text(path, platform, result)
    if text is None:
        return None
    try:
        return json.loads(strip_jsonc(text) if allow_comments else text)
    except json.JSONDecodeError as exc:
        result.errors.append(ScanError(platform, str(path), f"not valid JSON (line {exc.lineno})"))
    except RecursionError:
        result.errors.append(ScanError(platform, str(path), "skipped: JSON is nested too deeply"))
    return None


def read_toml(path: Path, platform: str, result: ScanResult) -> dict[str, Any] | None:
    """Read a TOML file (Codex uses TOML). Problems become ScanErrors."""
    text = _read_text(path, platform, result)
    if text is None:
        return None
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        result.errors.append(ScanError(platform, str(path), f"not valid TOML ({exc.args[0].split('(')[0].strip() if exc.args else 'parse error'})"))
    except RecursionError:
        result.errors.append(ScanError(platform, str(path), "skipped: TOML is nested too deeply"))
    return None


def system_dir(ctx: ScanContext, key: str, defaults: dict[str, Path]) -> Path | None:
    """Pick the OS-specific system folder for ``key``. Tests override via ctx.system_dirs."""
    if ctx.system_dirs is not None:
        return ctx.system_dirs.get(key)
    os_key = "linux" if ctx.platform_os.startswith("linux") else ctx.platform_os
    return defaults.get(os_key)


def json_files(folder: Path, platform: str, result: ScanResult) -> list[Path]:
    return [p for p in list_children(folder, platform, result) if p.is_file() and p.suffix == ".json"]


_IGNORED_NAMES = {".DS_Store", ".git", "Thumbs.db"}


def list_children(folder: Path, platform: str, result: ScanResult) -> list[Path]:
    """List a folder's entries.

    Hidden (dot) entries are included on purpose: an inventory tool must not
    let something hide by starting its name with a dot.
    """
    if not folder.is_dir():
        return []
    try:
        return sorted(p for p in folder.iterdir() if p.name not in _IGNORED_NAMES)
    except OSError as exc:
        result.errors.append(ScanError(platform, str(folder), f"could not list: {exc.strerror or type(exc).__name__}"))
        return []
