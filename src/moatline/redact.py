"""Secret masking.

Every string that comes from a config file passes through these functions
before it reaches a report. The goal is that a report can be pasted into a
chat or a ticket without leaking a credential.

Rules:
- Environment variable values and header values are never shown. Callers
  report only their names (see ``names_only``).
- ``${VAR}`` references are kept, because they are not secrets.
- Known token formats, long random-looking strings, and values of flags such
  as ``--api-key=...`` are replaced with ``[REDACTED]``.
- URLs lose their username, password, query string and fragment.
"""

from __future__ import annotations

import re
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit

REDACTED = "[REDACTED]"

_VAR_REF = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*(?::-[^}]*)?\}")

_KNOWN_TOKENS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),  # OpenAI / Anthropic style keys
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),  # GitHub tokens
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"xox[abposr]-[A-Za-z0-9\-]{10,}"),  # Slack tokens
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key IDs
    re.compile(r"AIza[0-9A-Za-z_\-]{30,}"),  # Google API keys
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),  # JWTs
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]

_SECRET_WORD = r"(?:api[_-]?key|access[_-]?key|secret|token|password|passwd|pwd|auth)(?:[_-][a-z]+)?"
# Command-line flags: --token abc, --api-key=abc, -password abc
_SECRET_FLAG = re.compile(rf"(?i)((?<![\w-])--?{_SECRET_WORD})(\s*=\s*|\s+)([^\s\"']+)")
# Assignments: token=abc, PASSWORD: abc, api_key="abc"
_SECRET_ASSIGN = re.compile(rf"(?i)(\b[A-Za-z0-9_]*{_SECRET_WORD})(\s*[=:]\s*[\"']?)([^\s\"']+)")
# A list item that is only a secret flag, so the next item is its value.
_SECRET_FLAG_ALONE = re.compile(rf"(?i)^--?{_SECRET_WORD}$")
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+([A-Za-z0-9._~+/\-]+=*)")

# Long strings of letters and digits that look random (hex or base64).
_LONG_RANDOM = re.compile(r"\b[A-Za-z0-9+/_\-]{32,}={0,2}")


def _looks_random(candidate: str) -> bool:
    """Random tokens mix letters and digits and rarely contain word separators.

    Long readable names such as "mcp-server-postgres-2024-edition" are kept.
    """
    has_digit = any(c.isdigit() for c in candidate)
    has_alpha = any(c.isalpha() for c in candidate)
    separators = sum(1 for c in candidate if c in "-_")
    return has_digit and has_alpha and "/" not in candidate.strip("/") and separators <= 3


def redact_text(value: str) -> str:
    """Return ``value`` with anything secret-looking replaced."""
    if not value:
        return value

    # Protect ${VAR} references so they survive the passes below.
    placeholders: list[str] = []

    def _stash(match: re.Match[str]) -> str:
        placeholders.append(match.group(0))
        return f"\x00{len(placeholders) - 1}\x00"

    text = _VAR_REF.sub(_stash, value)

    for pattern in _KNOWN_TOKENS:
        text = pattern.sub(REDACTED, text)

    text = _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", text)

    def _flag(match: re.Match[str]) -> str:
        flag_value = match.group(3)
        if flag_value.startswith("\x00") or flag_value == REDACTED:
            return match.group(0)
        return f"{match.group(1)}{match.group(2)}{REDACTED}"

    text = _SECRET_FLAG.sub(_flag, text)
    text = _SECRET_ASSIGN.sub(_flag, text)

    text = _LONG_RANDOM.sub(
        lambda m: REDACTED if _looks_random(m.group(0)) else m.group(0), text
    )

    for index, original in enumerate(placeholders):
        text = text.replace(f"\x00{index}\x00", original)
    return text


def redact_url(value: str) -> str:
    """Keep scheme, host, port and path. Drop credentials, query and fragment."""
    if not value:
        return value
    if _VAR_REF.fullmatch(value):
        return value
    try:
        parts = urlsplit(value)
    except ValueError:
        return redact_text(value)
    if not parts.scheme or not parts.netloc:
        return redact_text(value)
    host = parts.hostname or ""
    if ":" in host:  # IPv6 addresses keep their brackets
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:  # a port like ":abc" is malformed; show the text redacted instead
        return redact_text(value.split("?", 1)[0])
    if port:
        host = f"{host}:{port}"
    query = "[query removed]" if parts.query else ""
    cleaned = urlunsplit((parts.scheme, host, parts.path, "", ""))
    cleaned = redact_text(cleaned)
    return f"{cleaned}?{query}" if query else cleaned


def redact_list(values: Iterable[Any]) -> list[str]:
    """Redact a list of command arguments.

    Handles flags split across two items, such as ["--api-key", "abc"].
    """
    cleaned: list[str] = []
    hide_next = False
    for raw in values:
        value = str(raw)
        if hide_next and not _VAR_REF.fullmatch(value):
            cleaned.append(REDACTED)
        else:
            cleaned.append(redact_text(value))
        hide_next = bool(_SECRET_FLAG_ALONE.match(value))
    return cleaned


def names_only(mapping: Any) -> list[str]:
    """Return the sorted keys of a dict, never its values."""
    if not isinstance(mapping, dict):
        return []
    return sorted(str(k) for k in mapping.keys())


# Whole name parts only, so GIT_AUTHOR_NAME or MONKEY_MODE don't count.
_SECRET_NAME = re.compile(
    r"(?i)(?:^|[_\-.\s])(?:api[_-]?key|key|keys|token|secret|secrets|passw(?:or)?d|pwd|auth|authorization"
    r"|credentials?|cookie|bearer|pat)(?:$|[_\-.\s])"
)
_REFERENCE = re.compile(r"\$\{|^\$[A-Za-z_]|\{env:|\{input:")


_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def looks_secret_name(name: Any) -> bool:
    """True for names like GITHUB_TOKEN, X-Api-Key, Authorization or accessToken."""
    return bool(_SECRET_NAME.search(_CAMEL.sub("_", str(name))))


def literal_secret_names(mapping: Any) -> list[str]:
    """Names of entries whose value is a secret typed straight into the file.

    A value counts when it is not a reference such as ${VAR}, $VAR or
    ${input:id}, and either its name sounds secret (KEY, TOKEN, Authorization...)
    or the value itself looks like a token. Only names are returned, never values.
    """
    if not isinstance(mapping, dict):
        return []
    found = []
    for name, value in mapping.items():
        if not isinstance(value, str) or not value.strip():
            continue
        if _REFERENCE.search(value) or _plain_setting(value):
            continue
        if looks_secret_name(name) or redact_text(value) != value:
            found.append(str(name))
    return sorted(found)


# Only keys at least this long show their last 4 characters; for anything
# shorter, 4 characters would give away too much of the secret.
MIN_LENGTH_FOR_ENDING = 20


def secret_endings(*mappings: Any) -> dict[str, str]:
    """Last 4 characters of each long secret typed into the file, by name.

    Used only in the "secret typed into a file" finding, so a person can tell
    which key to rotate. Never part of the inventory output.
    """
    endings: dict[str, str] = {}
    for mapping in mappings:
        if not isinstance(mapping, dict):
            continue
        for name in literal_secret_names(mapping):
            value = str(mapping[name]).strip()
            if len(value) >= MIN_LENGTH_FOR_ENDING:
                endings[name] = value[-4:]
    return endings


_PLAIN_WORDS = {"true", "false", "yes", "no", "on", "off", "none", "null", "oauth", "basic", "bearer"}


def _plain_setting(value: str) -> bool:
    """Values that are settings, not secrets: switches, small numbers, paths, plain URLs."""
    text = value.strip()
    if text.lower() in _PLAIN_WORDS or (text.isdigit() and len(text) < 8):
        return True
    if text.startswith(("/", "~/", "./", "../")) and redact_text(text) == text:
        return True
    if text.lower().startswith(("http://", "https://")):
        return not url_has_secret(text)
    return False


def url_has_secret(value: Any) -> bool:
    """True when a URL carries a password or a token-looking value in its query."""
    if not isinstance(value, str) or _VAR_REF.fullmatch(value):
        return False
    try:
        parts = urlsplit(value)
    except ValueError:
        return redact_text(value) != value
    if parts.password:
        return True
    for pair in parts.query.split("&") if parts.query else []:
        name, _, val = pair.partition("=")
        if not val or _REFERENCE.search(val):
            continue
        if looks_secret_name(name) or redact_text(val) != val:
            return True
    return False


def last_four(secret: str) -> str:
    """Show only the last 4 characters of a secret, for findings that need it."""
    if len(secret) <= 4:
        return "****"
    return "****" + secret[-4:]
