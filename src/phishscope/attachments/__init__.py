"""Attachment forensics (v0.5).

Safe, in-memory inventory of message attachments: filename (verbatim),
declared vs magic-byte Content-Type, size, hashes, and archive
container inventory — all observation-only, never verdicts.

Safety boundary:
- Attachment bytes are analyzed **in memory only** — never written to
  disk (there is deliberately no ``--extract`` option).
- Attachments are never executed, never rendered.
- Archive members are listed by name only (never extracted);
  encrypted entries are never read (no password attempts).
- OLE stream contents are never interpreted (directory names only).

Modules:
- :mod:`phishscope.attachments.models` — AttachmentRecord /
  AttachmentObservation / AttachmentAnalysis dataclasses.
- :mod:`phishscope.attachments.identify` — magic-byte identification
  (stdlib, no libmagic).
- :mod:`phishscope.attachments.archives` — ZIP inventory (names only,
  depth-bounded, encrypted-aware).
- :mod:`phishscope.attachments.ole` — minimal OLE directory reader
  (storage/stream names only; VBA detection).
- :mod:`phishscope.attachments.observations` — observation-only
  forensics (facts with basis, never verdicts).
- :mod:`phishscope.attachments.analysis` — whole-message attachment
  analysis.
"""

from phishscope.attachments import analysis, archives, identify, observations, ole
from phishscope.attachments.analysis import (
    PARSER_NAME,
    PARSER_VERSION,
    analyze_attachments,
)
from phishscope.attachments.models import (
    ArchiveInventory,
    ArchiveMember,
    AttachmentAnalysis,
    AttachmentObservation,
    AttachmentRecord,
    IdentifiedType,
    OleInventory,
)
from phishscope.core.plugins import ModuleInfo, register

__all__ = [
    "PARSER_NAME",
    "PARSER_VERSION",
    "ArchiveInventory",
    "ArchiveMember",
    "AttachmentAnalysis",
    "AttachmentObservation",
    "AttachmentRecord",
    "IdentifiedType",
    "OleInventory",
    "analysis",
    "analyze_attachments",
    "archives",
    "identify",
    "observations",
    "ole",
]

register(
    ModuleInfo(
        name="attachments",
        description="Attachment forensics (in memory only): magic-byte "
        "identification, declared-vs-identified type observations, "
        "double extensions, macro-capable formats, archive inventory "
        "by name only (never extracted, never executed) (v0.5)",
        version="0.5.0",
        commands=["attachments"],
    )
)
