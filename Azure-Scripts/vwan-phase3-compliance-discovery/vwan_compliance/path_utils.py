"""Shared file-path resolution, used by both cmdb.py and azure_export.py so
the two input files behave identically: quotes/whitespace stripped, `~` and
relative paths expanded, a Windows-style path handed to a Linux/WSL
interpreter falls back to `/mnt/<drive>/...`, and a bad path re-prompts (up
to max_attempts) instead of raising a traceback.

The only behavioral difference between the two callers is that the Azure
export file is OPTIONAL: `optional=True` lets a blank answer at the
interactive prompt mean "skip this file" instead of "try again".
"""
from __future__ import annotations

import platform
import re
import sys
from pathlib import Path
from typing import Optional


class FilePathError(ValueError):
    pass


def clean_and_resolve(raw: str) -> Path:
    text = raw.strip()
    # Windows "Copy as path" wraps in double quotes; some shells/users use
    # single quotes. Strip a single matching pair if present.
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        text = text[1:-1].strip()

    path = Path(text).expanduser()

    if path.exists():
        return path

    # WSL fallback: a Windows-style path (C:\...) handed to a Linux
    # interpreter. Translate to /mnt/c/... and try that instead.
    if platform.system() != "Windows":
        wsl_path = _windows_to_wsl(text)
        if wsl_path is not None and wsl_path.exists():
            return wsl_path

    # Return the best-guess path even if it doesn't exist yet; validation
    # reports the specific reason (missing vs. wrong type vs. wrong ext).
    return path


def _windows_to_wsl(text: str) -> Optional[Path]:
    match = re.match(r"^([A-Za-z]):\\(.*)$", text)
    if not match:
        return None
    drive, rest = match.groups()
    rest = rest.replace("\\", "/")
    return Path(f"/mnt/{drive.lower()}/{rest}")


def validate_path(path: Path, valid_extensions: tuple[str, ...]) -> tuple[bool, str]:
    if not path.exists():
        return False, "does not exist"
    if not path.is_file():
        return False, "is not a file"
    if path.suffix.lower() not in valid_extensions:
        return False, f"unsupported extension '{path.suffix}' (expected {'/'.join(valid_extensions)})"
    try:
        with path.open("rb"):
            pass
    except OSError as exc:
        return False, f"not readable ({exc})"
    return True, ""


def resolve_path_interactive(
    cli_value: Optional[str],
    *,
    prompt_text: str,
    valid_extensions: tuple[str, ...],
    max_attempts: int = 3,
    optional: bool = False,
    error_cls: type = FilePathError,
) -> Optional[Path]:
    """Return a validated Path from `cli_value`, or an interactive prompt if
    it's None. If `optional=True`, a blank answer at the prompt returns None
    (skip) instead of counting as an invalid attempt. Never raises a raw
    EOFError/KeyboardInterrupt when stdin can't be read -- that's turned
    into `error_cls` instead of a traceback.
    """
    candidate = cli_value
    attempts = 0
    while True:
        if candidate is None:
            attempts += 1
            if attempts > max_attempts:
                raise error_cls(f"No valid file path provided after {max_attempts} attempts.")
            candidate = _prompt(prompt_text, error_cls)
            if optional and candidate == "":
                return None

        path = clean_and_resolve(candidate)
        ok, reason = validate_path(path, valid_extensions)
        if ok:
            return path

        print(f"Invalid file path ({reason}): {candidate!r}", file=sys.stderr)
        attempts += 1
        if attempts > max_attempts:
            raise error_cls(f"No valid file path provided after {max_attempts} attempts.")
        candidate = _prompt(prompt_text, error_cls)
        if optional and candidate == "":
            return None


def _prompt(prompt_text: str, error_cls: type) -> str:
    try:
        return input(prompt_text).strip()
    except EOFError as exc:
        raise error_cls(
            "No file path could be read (stdin is not interactive). "
            "Pass the path explicitly for CI/non-interactive runs."
        ) from exc
