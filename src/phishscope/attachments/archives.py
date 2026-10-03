"""Archive container inventory (v0.5).

ZIP members are listed **by name only** — they are never extracted to
disk, never executed, never rendered. Encrypted entries are detected
via the ZIP encryption flag and never read (no password attempts of
any kind). Nested archives are inventoried in memory with a strict
depth cap. Corrupt archives become warnings, never crashes.
"""

from __future__ import annotations

import io
import struct
import zipfile

from phishscope.attachments.models import ArchiveInventory, ArchiveMember
from phishscope.core.config import AppConfig
from phishscope.core.models import ParserWarning

_ENCRYPTED_FLAG = 0x1

_ARCHIVE_SUFFIXES = (
    ".zip",
    ".jar",
    ".docx",
    ".xlsx",
    ".pptx",
    ".pptm",
    ".docm",
    ".xlsm",
)


class ArchiveError(Exception):
    """Raised when an archive cannot be inventoried (becomes a warning)."""


def _is_nested_archive(name: str) -> bool:
    return name.lower().endswith(_ARCHIVE_SUFFIXES)


def inventory_zip(
    data: bytes,
    cfg: AppConfig,
    warnings: list[ParserWarning],
    part_index: str,
    depth: int = 0,
) -> ArchiveInventory:
    """Inventory a ZIP container's members (names only).

    ``depth`` tracks nested-archive recursion; archives nested deeper
    than ``cfg.max_archive_depth`` are noted, not opened.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
    except (zipfile.BadZipFile, EOFError, struct.error) as exc:
        raise ArchiveError(f"unreadable ZIP container: {exc}") from exc
    except Exception as exc:  # defensive: malformed input must not crash
        raise ArchiveError(f"unreadable ZIP container: {type(exc).__name__}") from exc

    total = len(infos)
    truncated = total > cfg.max_archive_entries
    members: list[ArchiveMember] = []
    encrypted_entries = 0
    nested: list[ArchiveInventory] = []

    for info in infos[: cfg.max_archive_entries]:
        encrypted = bool(info.flag_bits & _ENCRYPTED_FLAG)
        if encrypted:
            encrypted_entries += 1
        nested_flag = _is_nested_archive(info.filename) and not encrypted
        members.append(
            ArchiveMember(
                name=info.filename,
                size=None if encrypted else info.file_size,
                encrypted=encrypted,
                nested_archive=nested_flag,
            )
        )
        if nested_flag and not info.is_dir():
            if depth >= cfg.max_archive_depth:
                warnings.append(
                    ParserWarning(
                        code="archive-depth-capped",
                        detail=(
                            f"nested archive {info.filename!r} not opened: "
                            f"depth limit {cfg.max_archive_depth} reached"
                        ),
                        part=part_index,
                    )
                )
                continue
            if info.file_size > cfg.max_nested_member_bytes:
                warnings.append(
                    ParserWarning(
                        code="archive-member-too-large",
                        detail=(
                            f"nested archive {info.filename!r} not opened: "
                            f"{info.file_size} bytes exceeds "
                            f"{cfg.max_nested_member_bytes} byte member cap"
                        ),
                        part=part_index,
                    )
                )
                continue
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    nested_data = zf.read(info.filename)
            except RuntimeError as exc:  # encrypted despite flag, or needs password
                warnings.append(
                    ParserWarning(
                        code="archive-member-unreadable",
                        detail=(
                            f"could not read nested archive {info.filename!r}: {exc}"
                        ),
                        part=part_index,
                    )
                )
                continue
            except (zipfile.BadZipFile, EOFError, KeyError) as exc:
                warnings.append(
                    ParserWarning(
                        code="archive-member-unreadable",
                        detail=(
                            f"could not read nested archive {info.filename!r}: {exc}"
                        ),
                        part=part_index,
                    )
                )
                continue
            try:
                nested.append(
                    inventory_zip(nested_data, cfg, warnings, part_index, depth + 1)
                )
            except ArchiveError as exc:
                warnings.append(
                    ParserWarning(
                        code="archive-unreadable",
                        detail=f"nested archive {info.filename!r}: {exc}",
                        part=part_index,
                    )
                )

    if truncated:
        warnings.append(
            ParserWarning(
                code="archive-entries-capped",
                detail=(
                    f"archive lists {total} members; "
                    f"inventory capped at {cfg.max_archive_entries}"
                ),
                part=part_index,
            )
        )

    return ArchiveInventory(
        format="zip",
        member_count=total,
        members=members,
        truncated=truncated,
        encrypted_entries=encrypted_entries,
        nested_inventories=nested,
    )
