"""Cryptographic hashing for evidence identification.

Hashes are always computed over the original bytes *before* any
parsing, so the digest identifies exactly what was received.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

_CHUNK_SIZE = 1024 * 1024


class HashingError(Exception):
    """Raised when a file cannot be hashed."""


def sha256_bytes(data: bytes) -> str:
    """SHA-256 hex digest of an in-memory byte string."""
    return hashlib.sha256(data).hexdigest()


def hash_file(path: str | Path, chunk_size: int = _CHUNK_SIZE) -> tuple[int, str]:
    """Stream ``path`` and return ``(size_bytes, sha256_hexdigest)``.

    The file is opened read-only and never modified.
    """
    p = Path(path)
    if not p.is_file():
        raise HashingError(f"not a regular file: {path}")
    digest = hashlib.sha256()
    size = 0
    try:
        with p.open("rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
    except OSError as exc:
        raise HashingError(f"cannot read {path}: {exc}") from exc
    return size, digest.hexdigest()
