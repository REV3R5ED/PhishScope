"""Magic-byte file identification (v0.5).

Stdlib only — no libmagic. Identification is structural (what the
first bytes say the file is), reported alongside the filename
extension and the declared Content-Type so disagreements become
observations. Unknown content is reported as unknown, never guessed.
"""

from __future__ import annotations

from phishscope.attachments.models import IdentifiedType

# (magic prefix, category, label, detail)
_SIGNATURES: tuple[tuple[bytes, str, str, str], ...] = (
    (b"MZ", "executable", "windows-pe", "MZ header (PE executable)"),
    (b"\x7fELF", "executable", "elf", "ELF magic (Unix executable)"),
    (b"%PDF-", "document", "pdf", "PDF header"),
    (
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        "document",
        "ole",
        "OLE compound-file signature (legacy Office)",
    ),
    (b"PK\x03\x04", "archive", "zip", "ZIP local file header"),
    (b"PK\x05\x06", "archive", "zip-empty", "ZIP end-of-central-directory only"),
    (b"PK\x07\x08", "archive", "zip-spanned", "ZIP data descriptor signature"),
    (b"\x1f\x8b", "archive", "gzip", "gzip magic"),
    (b"Rar!\x1a\x07\x00", "archive", "rar", "RAR signature"),
    (b"7z\xbc\xaf\x27\x1c", "archive", "sevenzip", "7z signature"),
    (b"\x89PNG\r\n\x1a\n", "image", "png", "PNG signature"),
    (b"\xff\xd8\xff", "image", "jpeg", "JPEG SOI marker"),
    (b"GIF87a", "image", "gif", "GIF87a header"),
    (b"GIF89a", "image", "gif", "GIF89a header"),
    (b"BM", "image", "bmp", "BMP magic"),
    (b"II*\x00", "image", "tiff", "TIFF little-endian magic"),
    (b"MM\x00*", "image", "tiff", "TIFF big-endian magic"),
    (b"{\\rtf", "document", "rtf", "RTF header"),
    (b"<?xml", "text", "xml", "XML declaration"),
    (b"#!/", "executable", "script", "shebang line (executable script)"),
)


def _looks_like_html(data: bytes) -> bool:
    head = data[:512].lstrip()[:64].lower()
    return head.startswith(b"<html") or head.startswith(b"<!doctype html")


def _looks_like_text(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:4096]
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        try:
            sample.decode("latin-1")
        except UnicodeDecodeError:  # pragma: no cover - latin-1 never fails
            return False
        # latin-1 decodes anything; require mostly printable
        text = sample.decode("latin-1")
    else:
        text = sample.decode("utf-8")
    if not text:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return printable / len(text) >= 0.9


def identify(data: bytes) -> IdentifiedType:
    """Identify a file from its leading bytes.

    Returns ``empty`` for zero-length input and ``unknown`` when no
    signature matches — identification never guesses.
    """
    if not data:
        return IdentifiedType("empty", "empty", "zero-length content")
    for magic, category, label, detail in _SIGNATURES:
        if data.startswith(magic):
            return IdentifiedType(category, label, detail)
    if _looks_like_html(data):
        return IdentifiedType("text", "html", "HTML tag at start of content")
    if _looks_like_text(data):
        return IdentifiedType("text", "text", "printable text, no binary magic")
    return IdentifiedType(
        "unknown", "unknown", "no known magic bytes; not printable text"
    )
