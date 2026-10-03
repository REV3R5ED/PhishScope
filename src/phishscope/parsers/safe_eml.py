"""Safe .eml / RFC 5322 message parser (v0.1).

Defensive-first: the message is untrusted input. This parser

- uses only the stdlib ``email`` package,
- never renders HTML, never fetches remote content, never executes
  anything, and never extracts attachment content beyond hashing it,
- enforces hard safety bounds (message size, header size, MIME part
  count, multipart nesting depth) and rejects violations with a clean
  :class:`ParseError` instead of crashing,
- records every ``email`` package defect and decoding problem as a
  :class:`ParserWarning` instead of failing,
- keeps the raw bytes verbatim and separate: the normalized model
  carries only their SHA-256, never their content.
"""

from __future__ import annotations

import email
import email.policy
import email.utils
from datetime import timezone
from email.message import Message
from pathlib import Path

from phishscope import __version__
from phishscope.core.config import AppConfig
from phishscope.core.hashing import sha256_bytes
from phishscope.core.logging import utc_now_iso
from phishscope.core.models import (
    Address,
    Attachment,
    MessageDate,
    MimePart,
    NormalizedMessage,
    ParserWarning,
    Provenance,
    evidence_id_for,
)

PARSER_NAME = "phishscope.safe_eml"
PARSER_VERSION = "0.1.0"


# ---------------------------------------------------------------------------
# Errors (CLI exit 2)
# ---------------------------------------------------------------------------


class ParseError(Exception):
    """Base class for parser rejections."""


class MessageTooLarge(ParseError):
    def __init__(self, size: int, limit: int) -> None:
        super().__init__(
            f"message size {size:,} bytes exceeds the {limit:,} byte safety limit"
        )
        self.size = size
        self.limit = limit


class HeaderTooLarge(ParseError):
    def __init__(self, size: int, limit: int) -> None:
        super().__init__(
            f"header block {size:,} bytes exceeds the {limit:,} byte safety limit"
        )
        self.size = size
        self.limit = limit


class TooManyParts(ParseError):
    def __init__(self, count: int, limit: int) -> None:
        super().__init__(
            f"message exceeds the {limit} MIME part safety limit "
            f"({count} parts walked before aborting)"
        )
        self.count = count
        self.limit = limit


class MimeTooDeep(ParseError):
    def __init__(self, depth: int, limit: int) -> None:
        super().__init__(
            f"multipart nesting depth {depth} exceeds the {limit} level safety limit"
        )
        self.depth = depth
        self.limit = limit


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def _split_head(raw: bytes) -> tuple[bytes, bytes]:
    """Split raw message bytes into (header_block, body)."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            return raw[:idx], raw[idx + len(sep) :]
    return raw, b""


def _raw_header_value(head: bytes, name: str) -> str | None:
    """Verbatim (unfolded) value of the first ``name`` header in ``head``.

    The stdlib header objects normalize values (e.g. a Date header gains
    ``-0000``); the normalized model keeps the *verbatim* original
    string here, so evidence is never silently rewritten.
    """
    current: bytes | None = None
    unfolded: list[bytes] = []
    for line in head.split(b"\n"):
        line = line.rstrip(b"\r")
        if line[:1] in b" \t" and current is not None:
            current += b" " + line.strip()
        else:
            if current is not None:
                unfolded.append(current)
            current = line
    if current is not None:
        unfolded.append(current)
    wanted = name.lower().encode("ascii")
    for header_line in unfolded:
        hname, sep, hvalue = header_line.partition(b":")
        if not sep:
            continue
        if hname.strip().lower() == wanted:
            return hvalue.strip().decode("utf-8", "replace")
    return None


def parse_file(path: str | Path, cfg: AppConfig) -> tuple[NormalizedMessage, bytes]:
    """Parse the message at ``path``.

    Returns ``(normalized_message, raw_bytes)``. The raw bytes are
    returned verbatim for ``--show-raw``; they are never embedded in
    the normalized model.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"no such file: {path}")
    if p.is_dir():
        raise IsADirectoryError(f"not a regular file: {path}")
    if not p.is_file():
        raise ParseError(f"not a regular file: {path}")
    size = p.stat().st_size
    if size > cfg.max_message_size_bytes:
        raise MessageTooLarge(size, cfg.max_message_size_bytes)
    raw = p.read_bytes()
    if len(raw) > cfg.max_message_size_bytes:  # race-safe re-check
        raise MessageTooLarge(len(raw), cfg.max_message_size_bytes)
    return parse_bytes(raw, str(p), cfg)


def parse_bytes(
    raw: bytes, source_path: str, cfg: AppConfig
) -> tuple[NormalizedMessage, bytes]:
    """Parse raw message bytes into a normalized model.

    The SHA-256 is computed *before* any parsing, so the digest always
    identifies exactly the bytes received.
    """
    digest = sha256_bytes(raw)
    head, _ = _split_head(raw)
    if len(head) > cfg.max_header_size_bytes:
        raise HeaderTooLarge(len(head), cfg.max_header_size_bytes)

    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
    except Exception as exc:
        raise ParseError(f"message could not be parsed: {exc}") from exc

    warnings: list[ParserWarning] = []
    walker = _Walker(cfg, warnings)
    mime_tree = walker.walk(msg, "0", 0)

    for header_name in ("date", "from"):
        if msg.get(header_name) is None:
            warnings.append(
                ParserWarning(
                    code="missing-header",
                    detail=f"no {header_name.capitalize()} header present",
                )
            )

    from_list = _parse_address_list(msg, "from")
    return_path_list = _parse_address_list(msg, "return-path")
    message = NormalizedMessage(
        evidence_id=evidence_id_for(digest),
        source_path=source_path,
        sha256=digest,
        size_bytes=len(raw),
        date=_parse_date(msg, head),
        from_addr=from_list[0] if from_list else None,
        to=_parse_address_list(msg, "to"),
        cc=_parse_address_list(msg, "cc"),
        reply_to=_parse_address_list(msg, "reply-to"),
        return_path=return_path_list[0] if return_path_list else None,
        message_id=_header_str(msg, "message-id"),
        subject=_header_str(msg, "subject"),
        mime_tree=mime_tree,
        attachments=walker.attachments,
        parser_warnings=warnings,
        provenance=Provenance(
            parser_name=PARSER_NAME,
            parser_version=PARSER_VERSION,
            phishscope_version=__version__,
            analyzed_at_utc=utc_now_iso(),
        ),
    )
    return message, raw


# ---------------------------------------------------------------------------
# MIME tree walk
# ---------------------------------------------------------------------------


class _Walker:
    """Depth- and count-bounded MIME tree walker."""

    def __init__(self, cfg: AppConfig, warnings: list[ParserWarning]) -> None:
        self.cfg = cfg
        self.warnings = warnings
        self.part_count = 0
        self.attachments: list[Attachment] = []

    def walk(self, part: Message, index: str, depth: int) -> MimePart:
        if depth > self.cfg.max_mime_depth:
            raise MimeTooDeep(depth, self.cfg.max_mime_depth)
        self.part_count += 1
        if self.part_count > self.cfg.max_mime_parts:
            raise TooManyParts(self.part_count, self.cfg.max_mime_parts)

        for defect in part.defects:
            self.warnings.append(
                ParserWarning(
                    code="mime-defect",
                    detail=f"{type(defect).__name__}: {defect}",
                    part=index,
                )
            )

        content_type = part.get_content_type()
        filename = _safe_filename(part, index, self.warnings)

        if part.is_multipart():
            children: list[MimePart] = []
            payload = part.get_payload()
            subparts = payload if isinstance(payload, list) else []
            for i, sub in enumerate(subparts):
                children.append(self.walk(sub, f"{index}.{i}", depth + 1))
            size = sum(c.size_bytes for c in children)
            return MimePart(
                index=index,
                content_type=content_type,
                filename=None,
                size_bytes=size,
                is_attachment=False,
                sha256=None,
                children=children,
            )

        data = _decode_payload(part, index, self.warnings)
        digest = sha256_bytes(data) if data else None
        is_attachment = filename is not None or (
            part.get_content_disposition() == "attachment"
        )
        if is_attachment:
            self.attachments.append(
                Attachment(
                    filename=filename or f"unnamed-attachment-{index}",
                    mime_claim=content_type,
                    size_bytes=len(data),
                    sha256=digest or sha256_bytes(b""),
                    part_index=index,
                )
            )
        return MimePart(
            index=index,
            content_type=content_type,
            filename=filename,
            size_bytes=len(data),
            is_attachment=is_attachment,
            sha256=digest,
            children=[],
        )


def _safe_filename(
    part: Message, index: str, warnings: list[ParserWarning]
) -> str | None:
    """Best-effort filename extraction; malformed params become warnings."""
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


def _decode_payload(part: Message, index: str, warnings: list[ParserWarning]) -> bytes:
    """Decode one leaf part's payload to bytes.

    The bytes are used for size accounting and the SHA-256 only — they
    are discarded afterwards and never enter the normalized model.
    """
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
        # e.g. message/rfc822 sub-message: hash its serialized form.
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


# ---------------------------------------------------------------------------
# Header normalization
# ---------------------------------------------------------------------------


def _header_str(msg: Message, name: str) -> str | None:
    """Decoded header value, or None when absent/unreadable."""
    hdr = msg.get(name)
    if hdr is None:
        return None
    try:
        value = str(hdr).strip()
    except Exception:
        return None
    return value or None


def _parse_address_list(msg: Message, name: str) -> list[Address]:
    """Parse an address header into display-name/addr objects."""
    hdr = msg.get(name)
    if hdr is None:
        return []
    # Structured address headers (policy.default) expose `.addresses`;
    # anything else falls back to raw string parsing below.
    structured = getattr(hdr, "addresses", None)
    if structured:
        out: list[Address] = []
        for addr_obj in structured:
            try:
                out.append(
                    Address(
                        display_name=addr_obj.display_name or "",
                        addr=addr_obj.addr_spec or "",
                        raw=str(addr_obj),
                    )
                )
            except Exception:
                continue
        if out:
            return out
    # Fallback for malformed address headers: parse the raw string.
    try:
        raw_value = str(hdr)
    except Exception:
        return []
    out = []
    try:
        pairs = email.utils.getaddresses([raw_value])
    except Exception:
        return []
    for display, addr_spec in pairs:
        out.append(Address(display_name=display, addr=addr_spec, raw=raw_value))
    return out


def _parse_date(msg: Message, head: bytes) -> MessageDate:
    """Parse the Date header; never invent a timezone.

    The ``original`` is the verbatim header value from the raw bytes —
    the stdlib header object normalizes it (e.g. appending ``-0000``),
    which would silently rewrite evidence.
    """
    original = _raw_header_value(head, "date")
    if original is None:
        return MessageDate(original=None, utc=None, valid=False)
    try:
        dt = email.utils.parsedate_to_datetime(original)
    except (TypeError, ValueError):
        return MessageDate(original=original, utc=None, valid=False)
    if dt is None or dt.tzinfo is None:
        # Timezone-naive or unparseable: keep the claim verbatim.
        return MessageDate(original=original, utc=None, valid=False)
    return MessageDate(
        original=original, utc=dt.astimezone(timezone.utc).isoformat(), valid=True
    )
