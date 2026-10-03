"""Configuration profiles for PhishScope.

v0.1 keeps a single in-process config with the safety bounds from the
master plan. Later phases may add JSON profiles; the accessor seam is
:func:`default_config`.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AppConfig:
    """Runtime configuration and parser safety bounds."""

    max_message_size_bytes: int = 25 * 1024 * 1024
    """Reject messages larger than this (plan: 25 MB)."""

    max_header_size_bytes: int = 1024 * 1024
    """Reject messages whose header block exceeds this (plan: 1 MB)."""

    max_mime_parts: int = 200
    """Reject messages with more MIME parts than this (plan: 200)."""

    max_mime_depth: int = 16
    """Reject multipart nesting deeper than this (recursion guard)."""

    max_archive_depth: int = 3
    """Nested archives deeper than this are noted, not opened (v0.5)."""

    max_archive_entries: int = 500
    """Cap on inventoried archive members; excess becomes a warning (v0.5)."""

    max_nested_member_bytes: int = 10 * 1024 * 1024
    """Nested archive members larger than this are not opened (v0.5)."""

    max_attachment_warn_bytes: int = 10 * 1024 * 1024
    """Attachments at/above this size get an oversized-attachment
    observation (analyst awareness; content is still fully processed)."""

    display_truncate_len: int = 200
    """Header values longer than this are truncated in human output
    (full values are always present in --json)."""


class ConfigError(Exception):
    """Raised for invalid configuration."""


def default_config() -> AppConfig:
    """Return the default v0.1 configuration."""
    return AppConfig()
