"""Observation-only attachment forensics (v0.5).

Every function here reports *facts* about what the message carries —
magic bytes, filename shape, declared vs identified types, archive
structure — with the exact basis cited. Nothing here is a verdict;
heuristic judgments are v0.6 work.
"""

from __future__ import annotations

from phishscope.attachments.models import (
    ArchiveInventory,
    AttachmentObservation,
    AttachmentRecord,
)

_EXECUTABLE_EXTS = frozenset(
    {
        ".exe",
        ".dll",
        ".scr",
        ".com",
        ".pif",
        ".cpl",
        ".msi",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".wsf",
        ".wsh",
        ".jar",
        ".apk",
    }
)
_MACRO_FORMAT_EXTS = frozenset(
    {
        ".docm",
        ".xlsm",
        ".pptm",
        ".dotm",
        ".xltm",
        ".potm",
        ".xlam",
        ".doc",
        ".xls",
        ".ppt",
    }
)
_ARCHIVE_EXTS = frozenset({".zip", ".rar", ".7z", ".gz", ".tar", ".cab"})
_IMAGE_EXTS = frozenset({".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff"})
_TEXT_EXTS = frozenset({".txt", ".csv", ".log", ".md"})

# Identified labels that satisfy each extension family (no observation).
_EXTENSION_ACCEPTS: dict[str, frozenset[str]] = {
    ext: frozenset({"windows-pe", "elf", "script"}) for ext in _EXECUTABLE_EXTS
}
_EXTENSION_ACCEPTS.update(
    {ext: frozenset({"zip", "ole"}) for ext in _MACRO_FORMAT_EXTS}
)
_EXTENSION_ACCEPTS.update(
    {
        ext: frozenset({"zip", "zip-empty", "gzip", "rar", "sevenzip"})
        for ext in _ARCHIVE_EXTS
    }
)
_EXTENSION_ACCEPTS[".pdf"] = frozenset({"pdf"})
_EXTENSION_ACCEPTS[".png"] = frozenset({"png"})
_EXTENSION_ACCEPTS[".jpg"] = frozenset({"jpeg"})
_EXTENSION_ACCEPTS[".jpeg"] = frozenset({"jpeg"})
_EXTENSION_ACCEPTS[".gif"] = frozenset({"gif"})
_EXTENSION_ACCEPTS[".bmp"] = frozenset({"bmp"})
_EXTENSION_ACCEPTS[".tiff"] = frozenset({"tiff"})
_EXTENSION_ACCEPTS[".html"] = frozenset({"html"})
_EXTENSION_ACCEPTS[".htm"] = frozenset({"html"})
for ext in _TEXT_EXTS:
    _EXTENSION_ACCEPTS[ext] = frozenset({"text", "xml", "script"})

# Declared Content-Types considered compatible with each identified label.
_LABEL_ACCEPTS_MIME: dict[str, frozenset[str]] = {
    "windows-pe": frozenset({"application/x-msdownload", "application/x-dosexec"}),
    "elf": frozenset({"application/x-elf", "application/x-executable"}),
    "script": frozenset({"application/x-sh", "text/x-sh", "application/javascript"}),
    "pdf": frozenset({"application/pdf"}),
    "zip": frozenset({"application/zip", "application/x-zip-compressed"}),
    "ole": frozenset(
        {"application/x-ole-storage", "application/msword", "application/vnd.ms-office"}
    ),
    "gzip": frozenset({"application/gzip", "application/x-gzip"}),
    "rar": frozenset({"application/vnd.rar", "application/x-rar-compressed"}),
    "sevenzip": frozenset({"application/x-7z-compressed"}),
    "png": frozenset({"image/png"}),
    "jpeg": frozenset({"image/jpeg"}),
    "gif": frozenset({"image/gif"}),
    "bmp": frozenset({"image/bmp"}),
    "tiff": frozenset({"image/tiff"}),
    "html": frozenset({"text/html"}),
    "xml": frozenset({"text/xml", "application/xml"}),
    "text": frozenset({"text/plain"}),
    "rtf": frozenset({"application/rtf", "text/rtf"}),
}
_GENERIC_MIMES = frozenset({"application/octet-stream", "application/binary"})


def _obs(code: str, detail: str, basis: str) -> AttachmentObservation:
    return AttachmentObservation(code=code, detail=detail, basis=basis)


def extension_observations(record: AttachmentRecord) -> list[AttachmentObservation]:
    """Filename-shape observations: double extensions, type mismatches."""
    out: list[AttachmentObservation] = []
    chain = record.extension_chain
    identified = record.identified

    if len(chain) >= 2 and record.extension in _EXECUTABLE_EXTS:
        out.append(
            _obs(
                "double-extension",
                f"filename has {len(chain)} extensions "
                f"({' '.join(chain)}) ending in executable "
                f"{record.extension!r}; the inner extensions are camouflage",
                f"filename={record.filename!r}",
            )
        )

    if identified.label not in ("unknown", "empty"):
        accepts = _EXTENSION_ACCEPTS.get(record.extension)
        if accepts is not None and identified.label not in accepts:
            out.append(
                _obs(
                    "extension-type-mismatch",
                    f"filename extension {record.extension!r} disagrees with "
                    f"magic-byte identification {identified.label!r} "
                    f"({identified.detail})",
                    f"filename={record.filename!r} magic={identified.detail}",
                )
            )
    return out


def mime_observations(record: AttachmentRecord) -> list[AttachmentObservation]:
    """Declared Content-Type vs magic-byte identification."""
    out: list[AttachmentObservation] = []
    identified = record.identified
    if identified.label in ("unknown", "empty"):
        return out
    claimed = record.mime_claim.split(";")[0].strip().lower()
    if claimed in _GENERIC_MIMES or not claimed:
        return out  # generic claim carries no information; nothing to judge
    accepts = _LABEL_ACCEPTS_MIME.get(identified.label)
    if accepts is not None and claimed not in accepts:
        out.append(
            _obs(
                "declared-mime-mismatch",
                f"declared Content-Type {claimed!r} disagrees with magic-byte "
                f"identification {identified.label!r} ({identified.detail})",
                f"mime_claim={record.mime_claim!r} magic={identified.detail}",
            )
        )
    return out


def content_observations(record: AttachmentRecord) -> list[AttachmentObservation]:
    """Content-based observations: executables, scripts, macros, emptiness."""
    out: list[AttachmentObservation] = []
    identified = record.identified
    label = identified.label

    if record.size_bytes == 0:
        out.append(
            _obs(
                "empty-attachment",
                "attachment has zero-length content",
                f"filename={record.filename!r}",
            )
        )
        return out

    if label in ("windows-pe", "elf"):
        out.append(
            _obs(
                "executable-content",
                f"attachment content is a native executable ({identified.detail}); "
                "it was not executed",
                f"filename={record.filename!r} magic={identified.detail}",
            )
        )
    elif label == "script":
        out.append(
            _obs(
                "script-content",
                "attachment content is an executable script (shebang); "
                "it was not executed",
                f"filename={record.filename!r}",
            )
        )

    if record.extension in _MACRO_FORMAT_EXTS and label in ("zip", "ole"):
        out.append(
            _obs(
                "macro-capable-format",
                f"format {record.extension!r} can carry macros; presence of "
                "macro code is reported separately when structurally detected",
                f"filename={record.filename!r}",
            )
        )
    if record.ole is not None and record.ole.vba_storage_present:
        out.append(
            _obs(
                "vba-project-present",
                "OLE directory contains a VBA storage/stream: macro code is "
                "structurally present (never executed, never decompiled)",
                f"filename={record.filename!r} storages={record.ole.storages!r}",
            )
        )
    return out


def _archive_member_observations(
    inv: ArchiveInventory, record: AttachmentRecord
) -> list[AttachmentObservation]:
    out: list[AttachmentObservation] = []
    if inv.encrypted_entries:
        out.append(
            _obs(
                "password-protected",
                f"archive has {inv.encrypted_entries} encrypted member(s); "
                "contents cannot be inspected offline and no password was attempted",
                f"filename={record.filename!r}",
            )
        )
    for member in inv.members:
        stem = member.name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        final_ext = "." + stem.rsplit(".", 1)[-1].lower() if "." in stem else ""
        if final_ext in _EXECUTABLE_EXTS:
            out.append(
                _obs(
                    "archive-member-executable",
                    f"archive member {member.name!r} has an executable "
                    "extension; it was listed by name only, never extracted",
                    f"filename={record.filename!r} member={member.name!r}",
                )
            )
            break  # one observation per archive level is enough
    for nested in inv.nested_inventories:
        out.append(
            _obs(
                "nested-archive",
                "archive contains a nested archive that was inventoried "
                "in memory (depth-bounded); members were never extracted",
                f"filename={record.filename!r}",
            )
        )
        out.extend(_archive_member_observations(nested, record))
    return out


def archive_observations(record: AttachmentRecord) -> list[AttachmentObservation]:
    """Archive-structure observations (names only, never extracted)."""
    if record.archive is None:
        return []
    return _archive_member_observations(record.archive, record)


def ooxml_macro_observations(record: AttachmentRecord) -> list[AttachmentObservation]:
    """VBA project parts inside OOXML (ZIP-based Office) containers."""
    out: list[AttachmentObservation] = []
    if record.archive is None or record.identified.label != "zip":
        return out

    def _scan(inv: ArchiveInventory) -> bool:
        for member in inv.members:
            lowered = member.name.lower()
            if (
                "vbaproject.bin" in lowered
                or "vba" in lowered
                and lowered.endswith(".bin")
            ):
                return True
        return any(_scan(n) for n in inv.nested_inventories)

    if _scan(record.archive):
        out.append(
            _obs(
                "vba-project-present",
                "OOXML container holds a vbaProject.bin part: macro code is "
                "structurally present (never executed, never decompiled)",
                f"filename={record.filename!r}",
            )
        )
    return out


def size_observations(
    record: AttachmentRecord, warn_bytes: int
) -> list[AttachmentObservation]:
    """Size observations (analyst awareness; content still fully processed)."""
    if record.size_bytes >= warn_bytes:
        return [
            _obs(
                "oversized-attachment",
                f"attachment is {record.size_bytes} bytes (>= {warn_bytes} "
                "byte awareness threshold); it was still fully hashed and "
                "inventoried in memory",
                f"filename={record.filename!r} size={record.size_bytes}",
            )
        ]
    return []
