"""Disk cache used for --resume and for per-NIC effective-route caching.

The cache is a plain JSON file keyed by a caller-supplied string key (e.g. a
NIC resource ID, or "baseline"). It is intentionally simple: this is a
read-only discovery tool run periodically, not a database. Corrupt/missing
cache files are treated as empty rather than fatal.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

from .logging_config import get_logger

log = get_logger("cache")


class RunCache:
    def __init__(self, path: Path, enabled: bool):
        self.path = path
        self.enabled = enabled
        self._data: dict[str, Any] = {}
        if enabled and path.exists():
            try:
                self._data = json.loads(path.read_text(encoding="utf-8"))
                log.info("Resumed cache from %s (%d entries).", path, len(self._data))
            except (json.JSONDecodeError, OSError) as exc:
                log.warning("Could not read cache file %s (%s) - starting fresh.", path, exc)
                self._data = {}

    def get(self, key: str) -> Optional[Any]:
        if not self.enabled:
            return None
        return self._data.get(key)

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value

    def flush(self) -> None:
        if not self.enabled:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._data, default=str, indent=2), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError as exc:
            log.warning("Could not write cache file %s (%s).", self.path, exc)
