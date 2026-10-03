"""Normalized message model for PhishScope.

The model is *derived* from the raw message bytes; it never contains
them. Raw bytes are identified by SHA-256 and shown only via
``--show-raw`` behind a safety banner. Mutating a normalized model can
never touch the original evidence — the two are separate objects by
construction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Address:
    """A parsed email address: display name + addr-spec."""

    display_name: str
    addr: str
    raw: str  # the address as it appeared in the header (decoded)

    def to_dict(self) -> dict[str, Any]:
        return {
            "display_name": self.display_name,
            "addr": self.addr,
            "raw": self.raw,
        }


@dataclass
class MessageDate:
    """The Date header: original string plus an optional UTC normalization.

    A timezone is never invented: timezone-naive or unparseable dates
    keep ``utc`` as None and ``valid`` False.
    """

    original: str | None
    utc: str | None
    valid: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "original": self.original,
            "utc": self.utc,
            "valid": self.valid,
        }


@dataclass
class MimePart:
    """One node of the MIME structure tree.

    Only structure is recorded (content types, sizes, filenames) —
    part *content* is never decoded into the model in v0.1. Leaf
    payloads are hashed; the bytes themselves are discarded.
    """

    index: str  # dotted position, e.g. "0", "0.1", "0.2.1"
    content_type: str
    filename: str | None
    size_bytes: int  # decoded payload bytes (containers: sum of children)
    is_attachment: bool
    sha256: str | None  # leaf payload digest; None for containers
    children: list[MimePart] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "content_type": self.content_type,
            "filename": self.filename,
            "size_bytes": self.size_bytes,
            "is_attachment": self.is_attachment,
            "sha256": self.sha256,
            "children": [c.to_dict() for c in self.children],
        }


@dataclass
class Attachment:
    """Attachment inventory entry (v0.1: metadata + hash only).

    Content is never extracted in v0.1 — only the SHA-256 of the
    decoded payload is kept, so analysts can pivot on it without
    touching the payload.
    """

    filename: str
    mime_claim: str  # the Content-Type the message *claims*
    size_bytes: int
    sha256: str
    part_index: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "mime_claim": self.mime_claim,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "part_index": self.part_index,
        }


@dataclass
class ParserWarning:
    """A non-fatal parser observation (defects, encoding, truncation)."""

    code: str
    detail: str
    part: str | None = None  # MIME part index, when applicable

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "detail": self.detail,
            "part": self.part,
        }


@dataclass
class Provenance:
    """Which tool produced this analysis, and when."""

    parser_name: str
    parser_version: str
    phishscope_version: str
    analyzed_at_utc: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "parser_name": self.parser_name,
            "parser_version": self.parser_version,
            "phishscope_version": self.phishscope_version,
            "analyzed_at_utc": self.analyzed_at_utc,
        }


@dataclass
class NormalizedMessage:
    """The normalized, analyst-facing view of one message.

    Deterministic: :meth:`to_dict` emits fields in a fixed order and
    the CLI serializes with sorted keys, so identical input always
    yields identical JSON.
    """

    evidence_id: str  # PS-MSG-<12 hex chars of the raw SHA-256>
    source_path: str
    sha256: str  # of the original raw bytes, computed before parsing
    size_bytes: int
    date: MessageDate
    from_addr: Address | None
    to: list[Address]
    cc: list[Address]
    reply_to: list[Address]
    return_path: Address | None
    message_id: str | None
    subject: str | None
    mime_tree: MimePart
    attachments: list[Attachment]
    parser_warnings: list[ParserWarning]
    provenance: Provenance

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source_path": self.source_path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "date": self.date.to_dict(),
            "from": self.from_addr.to_dict() if self.from_addr else None,
            "to": [a.to_dict() for a in self.to],
            "cc": [a.to_dict() for a in self.cc],
            "reply_to": [a.to_dict() for a in self.reply_to],
            "return_path": self.return_path.to_dict() if self.return_path else None,
            "message_id": self.message_id,
            "subject": self.subject,
            "mime_tree": self.mime_tree.to_dict(),
            "attachments": [a.to_dict() for a in self.attachments],
            "parser_warnings": [w.to_dict() for w in self.parser_warnings],
            "provenance": self.provenance.to_dict(),
        }


def evidence_id_for(sha256_hex: str) -> str:
    """Stable evidence identifier derived from the raw-byte digest."""
    return "PS-MSG-" + sha256_hex[:12].upper()
