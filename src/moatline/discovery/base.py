"""Shared helpers for discovery modules.

Every path the scanner reads comes from a ScanContext, so tests can point it at
fake folders and never touch the real home directory.
"""

from __future__ import annotations

import json
import os
import sys
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


def read_json(path: Path, platform: str, result: ScanResult) -> Any | None:
    """Read a JSON file for reading only. Problems become ScanErrors, never exceptions."""
    if not path.is_file():
        return None
    result.scanned_files.append(str(path))
    try:
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            result.errors.append(ScanError(platform, str(path), f"skipped: file is larger than {MAX_FILE_BYTES} bytes"))
            return None
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        result.errors.append(ScanError(platform, str(path), f"not valid JSON (line {exc.lineno})"))
    except RecursionError:
        result.errors.append(ScanError(platform, str(path), "skipped: JSON is nested too deeply"))
    except UnicodeDecodeError:
        result.errors.append(ScanError(platform, str(path), "not valid UTF-8 text"))
    except OSError as exc:
        result.errors.append(ScanError(platform, str(path), f"could not read: {exc.strerror or type(exc).__name__}"))
    return None


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
