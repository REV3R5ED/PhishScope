"""Whole-message attachment forensics (v0.5).

:func:`analyze_attachments` walks the MIME tree with the same
depth/count bounds as the v0.1 parser, keeps each attachment's payload
**in memory only**, identifies it from magic bytes, inventories archive
containers by name, and derives observation-only facts.

Safety boundary (documented, tested):
- attachment bytes are never written to disk,
- never executed, never rendered,
- archive members are listed by name only (never extracted),
- encrypted archive entries are never read (no password attempts),
- stream contents of OLE containers are never interpreted.

``cfg`` carries the safety caps: ``max_mime_parts`` / ``max_mime_depth``
(tree bounds, shared with v0.1), ``max_archive_depth``,
``max_archive_entries``, ``max_nested_member_bytes`` (archive
inventory bounds), and ``max_attachment_warn_bytes`` (oversized
awareness threshold — content is still fully processed).
"""

from __future__ import annotations

import email
import hashlib
from email.message import Message

from phishscope import __version__
from phishscope.attachments import archives
from phishscope.attachments import identify as identify_mod
from phishscope.attachments import observations as obs
from phishscope.attachments.models import (
    ArchiveInventory,
    AttachmentAnalysis,
    AttachmentObservation,
    AttachmentRecord,
    OleInventory,
)
from phishscope.attachments.ole import OleError, read_directory
from phishscope.core.config import AppConfig
from phishscope.core.hashing import sha256_bytes
from phishscope.core.logging import utc_now_iso
from phishscope.core.models import ParserWarning, Provenance, evidence_id_for

PARSER_NAME = "phishscope.attachments"
PARSER_VERSION = "0.5.0"


class _TreeError(Exception):
    """MIME tree exceeded a safety bound."""


def _decode_payload(part: Message, index: str, warnings: list[ParserWarning]) -> bytes:
    """Decode one leaf part's payload to bytes (in memory only)."""
    try:
        decoded = part.get_payload(decode=True)
    except Exception as exc:
        warnings.append(
            ParserWarning(
                code="payload-decode-failed",
                detail=f"payload could not be transfer-decoded: {exc}",
                part=index,
            )
        )
        return b""
    if decoded is None:
        sub = part.get_payload()
        if isinstance(sub, Message):
            try:
                return sub.as_bytes()
            except Exception as exc:
                warnings.append(
                    ParserWarning(
                        code="payload-decode-failed",
                        detail=f"nested message could not be serialized: {exc}",
                        part=index,
                    )
                )
                return b""
        if isinstance(sub, bytes):
            return sub
        if isinstance(sub, str):
            return sub.encode("utf-8", "replace")
        return b""
    if isinstance(decoded, (bytes, bytearray)):
        return bytes(decoded)
    return str(decoded).encode("utf-8", "replace")


def _safe_filename(
    part: Message, index: str, warnings: list[ParserWarning]
) -> str | None:
    try:
        return part.get_filename()
    except Exception as exc:
        warnings.append(
            ParserWarning(
                code="filename-decode-failed",
                detail=f"could not decode attachment filename: {exc}",
                part=index,
            )
        )
        return None


def _extension_chain(filename: str) -> tuple[str, list[str]]:
    """Return (final_extension, all_extensions) lowercased."""
    base = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    parts = base.split(".")
    if len(parts) < 2 or not parts[-1]:
        return "", []
    chain = [p.lower() for p in parts[1:] if p]
    return ("." + chain[-1]) if chain else "", chain


class _Attachment:
    """In-memory attachment candidate from the MIME walk."""

    def __init__(
        self,
        filename: str,
        part_index: str,
        disposition: str | None,
        mime_claim: str,
        data: bytes,
    ) -> None:
        self.filename = filename
        self.part_index = part_index
        self.disposition = disposition
        self.mime_claim = mime_claim
        self.data = data


def _collect(
    part: Message,
    index: str,
    depth: int,
    cfg: AppConfig,
    warnings: list[ParserWarning],
    counter: list[int],
    out: list[_Attachment],
) -> None:
    if depth > cfg.max_mime_depth:
        raise _TreeError(f"MIME depth {depth} exceeds {cfg.max_mime_depth}")
    counter[0] += 1
    if counter[0] > cfg.max_mime_parts:
        raise _TreeError(f"MIME part count exceeds {cfg.max_mime_parts}")

    for defect in part.defects:
        warnings.append(
            ParserWarning(
                code="mime-defect",
                detail=f"{type(defect).__name__}: {defect}",
                part=index,
            )
        )

    if part.is_multipart():
        payload = part.get_payload()
        subparts = payload if isinstance(payload, list) else []
        for i, sub in enumerate(subparts):
            _collect(sub, f"{index}.{i}", depth + 1, cfg, warnings, counter, out)
        return

    data = _decode_payload(part, index, warnings)
    filename = _safe_filename(part, index, warnings)
    disposition = part.get_content_disposition()
    is_attachment = filename is not None or disposition == "attachment"
    if is_attachment:
        out.append(
            _Attachment(
                filename=filename or f"unnamed-attachment-{index}",
                part_index=index,
                disposition=disposition,
                mime_claim=part.get_content_type(),
                data=data,
            )
        )


def _hashes(data: bytes) -> tuple[str, str]:
    """SHA-256 and MD5 (pivot hash, not a security control), streamed."""
    sha = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False)
    for i in range(0, len(data), 65536):
        chunk = data[i : i + 65536]
        sha.update(chunk)
        md5.update(chunk)
    return sha.hexdigest(), md5.hexdigest()


def _analyze_one(
    att: _Attachment, cfg: AppConfig, warnings: list[ParserWarning]
) -> AttachmentRecord:
    sha256, md5 = _hashes(att.data)
    identified = identify_mod.identify(att.data)
    extension, chain = _extension_chain(att.filename)

    archive: ArchiveInventory | None = None
    ole: OleInventory | None = None

    if identified.label == "zip" or (
        extension == ".zip" and identified.label not in ("empty",)
    ):
        try:
            archive = archives.inventory_zip(att.data, cfg, warnings, att.part_index)
        except archives.ArchiveError as exc:
            warnings.append(
                ParserWarning(
                    code="archive-unreadable",
                    detail=str(exc),
                    part=att.part_index,
                )
            )
    elif identified.label == "ole":
        try:
            ole = read_directory(att.data)
        except OleError as exc:
            warnings.append(
                ParserWarning(
                    code="ole-unreadable",
                    detail=str(exc),
                    part=att.part_index,
                )
            )

    record = AttachmentRecord(
        filename=att.filename,
        part_index=att.part_index,
        content_disposition=att.disposition,
        mime_claim=att.mime_claim,
        size_bytes=len(att.data),
        sha256=sha256,
        md5=md5,
        identified=identified,
        extension=extension,
        extension_chain=chain,
        archive=archive,
        ole=ole,
    )

    observations: list[AttachmentObservation] = []
    observations.extend(obs.extension_observations(record))
    observations.extend(obs.mime_observations(record))
    observations.extend(obs.content_observations(record))
    observations.extend(obs.archive_observations(record))
    observations.extend(obs.ooxml_macro_observations(record))
    observations.extend(obs.size_observations(record, cfg.max_attachment_warn_bytes))
    record.observations = observations
    record.observation_codes = [o.code for o in observations]
    return record


def analyze_attachments(
    raw: bytes, source_path: str, cfg: AppConfig
) -> AttachmentAnalysis:
    """Inventory a message's attachments (in memory only, never on disk)."""
    digest = sha256_bytes(raw)
    warnings: list[ParserWarning] = []

    if len(raw) > cfg.max_message_size_bytes:
        raise ValueError(
            f"message is {len(raw)} bytes, exceeding "
            f"{cfg.max_message_size_bytes} byte limit"
        )

    try:
        msg = email.message_from_bytes(raw)
    except Exception as exc:
        raise ValueError(f"message could not be parsed: {exc}") from exc

    found: list[_Attachment] = []
    try:
        _collect(msg, "0", 0, cfg, warnings, [0], found)
    except _TreeError as exc:
        raise ValueError(str(exc)) from exc

    records = [_analyze_one(att, cfg, warnings) for att in found]

    message_observations: list[AttachmentObservation] = []
    if records:
        message_observations.append(
            AttachmentObservation(
                code="attachment-count",
                detail=f"message carries {len(records)} attachment(s)",
                basis=f"count={len(records)}",
            )
        )
    else:
        message_observations.append(
            AttachmentObservation(
                code="no-attachments",
                detail="message carries no attachments",
                basis="count=0",
            )
        )

    provenance = Provenance(
        parser_name=PARSER_NAME,
        parser_version=PARSER_VERSION,
        phishscope_version=__version__,
        analyzed_at_utc=utc_now_iso(),
    )
    return AttachmentAnalysis(
        evidence_id=evidence_id_for(digest),
        source_path=source_path,
        sha256=digest,
        attachments=records,
        observations=message_observations,
        parser_warnings=warnings,
        provenance=provenance,
    )
