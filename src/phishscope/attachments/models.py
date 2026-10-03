"""Normalized attachment models for PhishScope v0.5.

An :class:`AttachmentRecord` describes one *observed* attachment exactly
as carried by the message: filename verbatim, the Content-Type the
message *claims*, the type identified from magic bytes, size, hashes,
and the safety-bounded inventory of any archive container. Observations
are facts with a basis, never verdicts.

Safety boundary: attachment bytes are analyzed **in memory only**.
They are never written to disk, never executed, never rendered, and
archive members are listed by name only (never extracted). There is
deliberately no ``--extract`` option in v0.5.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class IdentifiedType:
    """File type identified from magic bytes (stdlib, no libmagic)."""

    category: (
        str  # e.g. "executable", "document", "archive", "image", "text", "unknown"
    )
    label: str  # e.g. "windows-pe", "pdf", "zip", "ole", "empty"
    detail: str  # which magic bytes matched, e.g. "MZ header (PE)"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "label": self.label,
            "detail": self.detail,
        }


@dataclass
class ArchiveMember:
    """One member of an archive container — name only, never extracted."""

    name: str
    size: int | None  # None when unknown (e.g. encrypted entry)
    encrypted: bool
    nested_archive: bool  # member is itself an archive (inventoried separately)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "size": self.size,
            "encrypted": self.encrypted,
            "nested_archive": self.nested_archive,
        }


@dataclass
class ArchiveInventory:
    """Safety-bounded inventory of an archive attachment's contents."""

    format: str  # "zip", ...
    member_count: int  # total members seen (may exceed len(members))
    members: list[ArchiveMember]  # capped at cfg.max_archive_entries
    truncated: bool  # True when members were capped
    encrypted_entries: int  # members with the encryption flag set
    nested_inventories: list[ArchiveInventory] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "member_count": self.member_count,
            "members": [m.to_dict() for m in self.members],
            "truncated": self.truncated,
            "encrypted_entries": self.encrypted_entries,
            "nested_inventories": [n.to_dict() for n in self.nested_inventories],
        }


@dataclass
class OleInventory:
    """Structural inventory of an OLE (compound file) container.

    Only the directory (storage/stream names) is read — stream contents
    are never interpreted.
    """

    storages: list[str]
    streams: list[str]
    vba_storage_present: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "storages": self.storages,
            "streams": self.streams,
            "vba_storage_present": self.vba_storage_present,
        }


@dataclass
class AttachmentObservation:
    """One observation-only fact about an attachment.

    ``code`` is a stable machine-readable tag (e.g.
    ``double-extension``); ``detail`` is human-readable; ``basis`` cites
    the exact evidence (filename, magic detail, member name). Never a
    verdict.
    """

    code: str
    detail: str
    basis: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "detail": self.detail,
            "basis": self.basis,
        }


@dataclass
class AttachmentRecord:
    """One observed attachment with identification and observations."""

    filename: str  # verbatim as carried by the message
    part_index: str  # MIME part index, e.g. "0.2"
    content_disposition: str | None
    mime_claim: str  # the Content-Type the message *claims*
    size_bytes: int
    sha256: str
    md5: str  # pivot hash, not a security control
    identified: IdentifiedType  # magic-byte identification
    extension: str  # lowercased final extension, "" when none
    extension_chain: list[str]  # all dot-parts, e.g. ["pdf", "exe"]
    archive: ArchiveInventory | None = None
    ole: OleInventory | None = None
    observation_codes: list[str] = field(default_factory=list)
    observations: list[AttachmentObservation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "part_index": self.part_index,
            "content_disposition": self.content_disposition,
            "mime_claim": self.mime_claim,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "md5": self.md5,
            "identified": self.identified.to_dict(),
            "extension": self.extension,
            "extension_chain": self.extension_chain,
            "archive": self.archive.to_dict() if self.archive else None,
            "ole": self.ole.to_dict() if self.ole else None,
            "observation_codes": self.observation_codes,
            "observations": [o.to_dict() for o in self.observations],
        }


@dataclass
class AttachmentAnalysis:
    """Whole-message attachment inventory."""

    evidence_id: str
    source_path: str
    sha256: str  # of the raw message bytes
    attachments: list[AttachmentRecord]
    observations: list[AttachmentObservation]  # message-level
    parser_warnings: list[Any]
    provenance: Any

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source_path": self.source_path,
            "sha256": self.sha256,
            "attachments": [a.to_dict() for a in self.attachments],
            "observations": [o.to_dict() for o in self.observations],
            "parser_warnings": [
                w.to_dict() if hasattr(w, "to_dict") else w
                for w in self.parser_warnings
            ],
            "provenance": self.provenance.to_dict()
            if hasattr(self.provenance, "to_dict")
            else self.provenance,
        }
