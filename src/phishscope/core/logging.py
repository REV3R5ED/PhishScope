"""Logging and audit trail for PhishScope.

Every CLI invocation appends a JSON record to the local audit log.
Logging is best effort: it never breaks a run.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("phishscope")


def configure_logging(verbose: bool = False) -> None:
    """Configure the ``phishscope`` logger (stderr diagnostics only)."""
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("phishscope: %(levelname)s: %(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.DEBUG if verbose else logging.WARNING)
    log.propagate = False


def get_logger() -> logging.Logger:
    """Return the ``phishscope`` logger."""
    return log


def utc_now_iso() -> str:
    """Current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _audit_path() -> Path:
    base = os.environ.get("PHISHCOPE_STATE_DIR") or str(Path.home() / ".phishscope")
    return Path(base) / "audit.log"


def audit_log(record: dict[str, Any]) -> None:
    """Append a JSON audit record. Never raises."""
    try:
        path = _audit_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        entry = {"ts": utc_now_iso(), **record}
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
    except Exception as exc:  # pragma: no cover - best effort by design
        log.debug("audit log write failed: %s", exc)
