"""Minimal OLE (compound file) directory reader (v0.5).

Reads only the OLE header, the FAT, and the directory stream — i.e.
storage and stream *names*. Stream contents are never interpreted.
This is enough to detect a VBA project structurally (a storage named
``VBA`` / stream ``_VBA_PROJECT_CUR``) without executing or parsing
any macro code.

Malformed input raises :class:`OleError`; callers turn that into a
warning, never a crash.
"""

from __future__ import annotations

import struct

from phishscope.attachments.models import OleInventory

_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

_FREESECT = 0xFFFFFFFF
_ENDOFCHAIN = 0xFFFFFFFE
_FATSECT = 0xFFFFFFFD
_NOSTREAM = 0xFFFFFFFF

_DIR_ENTRY_SIZE = 128


class OleError(Exception):
    """Raised when OLE structure cannot be read."""


def _u16(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("<H", data, offset)[0])


def _u32(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("<I", data, offset)[0])


def _i32(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("<i", data, offset)[0])


def _read_sector(data: bytes, sector: int, sector_size: int) -> bytes:
    start = 512 + sector * sector_size
    end = start + sector_size
    if start < 512 or end > len(data):
        raise OleError(f"sector {sector} out of range")
    return data[start:end]


def _fat_chain(data: bytes, fat: list[int], start: int, sector_size: int) -> bytes:
    out = bytearray()
    sector = start
    seen = 0
    while sector != _ENDOFCHAIN:
        if sector in (_FREESECT, _FATSECT) or sector >= len(fat):
            raise OleError(f"bad FAT chain at sector {sector}")
        out += _read_sector(data, sector, sector_size)
        sector = fat[sector]
        seen += 1
        if seen > len(fat) + 1:  # cycle guard
            raise OleError("FAT chain cycle detected")
    return bytes(out)


def read_directory(data: bytes) -> OleInventory:
    """Read storage/stream names from an OLE compound file.

    Returns an :class:`OleInventory`; raises :class:`OleError` on
    malformed input.
    """
    if len(data) < 512 or not data.startswith(_SIGNATURE):
        raise OleError("missing OLE signature")
    header = data[:512]

    sector_shift = _u16(header, 30)
    if sector_shift not in (9, 12):
        raise OleError(f"unsupported sector shift {sector_shift}")
    sector_size = 1 << sector_shift

    num_fat_sectors = _u32(header, 44)
    first_dir_sector = _u32(header, 48)
    if first_dir_sector in (_FREESECT, _ENDOFCHAIN):
        raise OleError("no directory stream")

    # DIFAT: first 109 FAT sector locations live in the header.
    difat: list[int] = []
    for i in range(109):
        sect = _u32(header, 76 + i * 4)
        if sect == _FREESECT:
            break
        difat.append(sect)
    if len(difat) < num_fat_sectors:
        raise OleError("DIFAT chain across sectors not supported in v0.5")

    fat: list[int] = []
    for sect in difat[:num_fat_sectors]:
        raw = _read_sector(data, sect, sector_size)
        for i in range(0, len(raw), 4):
            fat.append(_u32(raw, i))

    directory = _fat_chain(data, fat, first_dir_sector, sector_size)
    if len(directory) < _DIR_ENTRY_SIZE:
        raise OleError("directory stream too short")

    storages: list[str] = []
    streams: list[str] = []

    # BFS from the root entry's child through sibling links.
    root = directory[:_DIR_ENTRY_SIZE]
    queue = [_u32(root, 76)]
    visited: set[int] = set()
    while queue:
        entry_id = queue.pop(0)
        if entry_id in (_NOSTREAM,) or entry_id in visited:
            continue
        visited.add(entry_id)
        off = entry_id * _DIR_ENTRY_SIZE
        entry = directory[off : off + _DIR_ENTRY_SIZE]
        if len(entry) < _DIR_ENTRY_SIZE:
            raise OleError(f"directory entry {entry_id} truncated")
        name_len = _u16(entry, 64)
        if name_len < 2 or name_len > 64:
            raise OleError(f"directory entry {entry_id} has bad name length")
        try:
            name = entry[: name_len - 2].decode("utf-16-le")
        except UnicodeDecodeError as exc:
            raise OleError(f"directory entry {entry_id} name undecodable") from exc
        obj_type = entry[66]
        if obj_type == 1:
            storages.append(name)
        elif obj_type == 2:
            streams.append(name)
        # Siblings and children (root itself is type 5, skipped as a name).
        for link_off in (68, 72, 76):
            link = _i32(entry, link_off)
            if link >= 0:
                queue.append(link)
        if len(visited) > 1024:  # sanity cap
            raise OleError("directory graph too large")

    names_upper = [n.upper() for n in storages + streams]
    vba_present = any("VBA" in n for n in names_upper)
    return OleInventory(
        storages=storages,
        streams=streams,
        vba_storage_present=vba_present,
    )
