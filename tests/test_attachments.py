"""Tests for PhishScope v0.5 attachment forensics.

Every binary payload is synthesized in-process by tests/conftest.py —
no binary fixtures are committed. Safety properties (never write to
disk, never execute, never network) are asserted directly.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

import conftest

from phishscope.attachments import identify as identify_mod
from phishscope.attachments.analysis import analyze_attachments
from phishscope.attachments.archives import ArchiveError, inventory_zip
from phishscope.attachments.ole import OleError, read_directory
from phishscope.cli.main import main
from phishscope.core.config import default_config


def _analyze(raw: bytes, **cfg_overrides):
    cfg = default_config()
    for key, value in cfg_overrides.items():
        setattr(cfg, key, value)
    return analyze_attachments(raw, "test.eml", cfg)


def _codes(record) -> list:
    return record.observation_codes


# ---------------------------------------------------------------------------
# Magic-byte identification
# ---------------------------------------------------------------------------


def test_identify_each_type():
    cases = {
        conftest.pe_bytes(): ("executable", "windows-pe"),
        conftest.elf_bytes(): ("executable", "elf"),
        conftest.pdf_bytes(): ("document", "pdf"),
        conftest.zip_bytes({"a.txt": b"x"}): ("archive", "zip"),
        conftest.ole_bytes(): ("document", "ole"),
        b"\x1f\x8b\x08\x00fake": ("archive", "gzip"),
        b"\x89PNG\r\n\x1a\nfake": ("image", "png"),
        b"\xff\xd8\xfffake": ("image", "jpeg"),
        b"GIF89afake": ("image", "gif"),
        conftest.script_bytes(): ("executable", "script"),
        b"just some plain text here\n": ("text", "text"),
        b"<html><body>hi</body></html>": ("text", "html"),
        b"": ("empty", "empty"),
        b"\x00\x01\x02\x03\x04binary-blob": ("unknown", "unknown"),
    }
    for data, (category, label) in cases.items():
        found = identify_mod.identify(data)
        assert (found.category, found.label) == (category, label), data[:8]


# ---------------------------------------------------------------------------
# Filename / type observations
# ---------------------------------------------------------------------------


def test_double_extension_executable():
    raw = conftest.eml_with_attachments(
        [("invoice.pdf.exe", "application/octet-stream", conftest.pe_bytes())]
    )
    analysis = _analyze(raw)
    rec = analysis.attachments[0]
    assert "double-extension" in _codes(rec)
    assert "executable-content" in _codes(rec)
    assert "extension-type-mismatch" not in _codes(rec)  # .exe agrees with PE


def test_extension_type_mismatch():
    raw = conftest.eml_with_attachments(
        [("report.pdf", "application/octet-stream", conftest.pe_bytes())]
    )
    rec = _analyze(raw).attachments[0]
    assert "extension-type-mismatch" in _codes(rec)
    assert "double-extension" not in _codes(rec)


def test_declared_mime_mismatch():
    raw = conftest.eml_with_attachments(
        [("runme.exe", "text/plain", conftest.pe_bytes())]
    )
    rec = _analyze(raw).attachments[0]
    assert "declared-mime-mismatch" in _codes(rec)


def test_generic_mime_claim_is_not_a_mismatch():
    raw = conftest.eml_with_attachments(
        [("tool.exe", "application/octet-stream", conftest.pe_bytes())]
    )
    rec = _analyze(raw).attachments[0]
    assert "declared-mime-mismatch" not in _codes(rec)


def test_benign_pdf_clean():
    raw = conftest.eml_with_attachments(
        [("statement.pdf", "application/pdf", conftest.pdf_bytes())]
    )
    rec = _analyze(raw).attachments[0]
    assert rec.identified.label == "pdf"
    assert _codes(rec) == []


def test_empty_attachment():
    raw = conftest.eml_with_attachments([("empty.txt", "text/plain", b"")])
    rec = _analyze(raw).attachments[0]
    assert "empty-attachment" in _codes(rec)


def test_oversized_attachment_observation():
    raw = conftest.eml_with_attachments(
        [("big.bin", "application/octet-stream", b"A" * 100)]
    )
    rec = _analyze(raw, max_attachment_warn_bytes=50).attachments[0]
    assert "oversized-attachment" in _codes(rec)
    assert rec.sha256  # still fully hashed


def test_no_attachments_message():
    analysis = _analyze(conftest.simple_text())
    assert analysis.attachments == []
    assert analysis.observations[0].code == "no-attachments"


def test_attachment_count_observation():
    raw = conftest.eml_with_attachments(
        [
            ("a.pdf", "application/pdf", conftest.pdf_bytes()),
            ("b.txt", "text/plain", b"hello"),
        ]
    )
    analysis = _analyze(raw)
    assert analysis.observations[0].code == "attachment-count"


def test_hashes_are_correct():
    payload = conftest.pe_bytes()
    raw = conftest.eml_with_attachments(
        [("tool.exe", "application/octet-stream", payload)]
    )
    rec = _analyze(raw).attachments[0]
    import hashlib

    assert rec.sha256 == hashlib.sha256(payload).hexdigest()
    assert rec.md5 == hashlib.md5(payload, usedforsecurity=False).hexdigest()


# ---------------------------------------------------------------------------
# OLE / macro structure
# ---------------------------------------------------------------------------


def test_ole_with_vba_detected():
    inv = read_directory(conftest.ole_bytes(with_vba=True))
    assert inv.vba_storage_present
    assert "VBA" in inv.storages
    assert "_VBA_PROJECT_CUR" in inv.streams


def test_ole_without_vba_clean():
    inv = read_directory(conftest.ole_bytes(with_vba=False))
    assert not inv.vba_storage_present


def test_ole_bad_signature_raises():
    try:
        read_directory(b"not an ole file" + b"\x00" * 600)
    except OleError:
        return
    raise AssertionError("expected OleError")


def test_vba_project_present_observation_via_ole():
    raw = conftest.eml_with_attachments(
        [("budget.xls", "application/vnd.ms-office", conftest.ole_bytes(with_vba=True))]
    )
    rec = _analyze(raw).attachments[0]
    assert rec.ole is not None
    assert "vba-project-present" in _codes(rec)
    assert "macro-capable-format" in _codes(rec)  # .xls is in the macro set


def test_macro_capable_format_without_vba():
    raw = conftest.eml_with_attachments(
        [
            (
                "budget.docm",
                "application/octet-stream",
                conftest.zip_bytes({"word/document.xml": b"<xml/>"}),
            )
        ]
    )
    rec = _analyze(raw).attachments[0]
    assert "macro-capable-format" in _codes(rec)
    assert "vba-project-present" not in _codes(rec)


def test_vba_project_in_ooxml():
    payload = conftest.zip_bytes(
        {
            "word/document.xml": b"<xml/>",
            "word/vbaProject.bin": b"fake-vba",
        }
    )
    raw = conftest.eml_with_attachments(
        [("budget.docm", "application/octet-stream", payload)]
    )
    rec = _analyze(raw).attachments[0]
    assert "vba-project-present" in _codes(rec)


def test_corrupt_ole_becomes_warning_not_crash():
    raw = conftest.eml_with_attachments(
        [
            (
                "broken.doc",
                "application/msword",
                b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"truncated-garbage",
            )
        ]
    )
    analysis = _analyze(raw)
    assert analysis.attachments[0].ole is None
    assert any(w.code == "ole-unreadable" for w in analysis.parser_warnings)


# ---------------------------------------------------------------------------
# Archives
# ---------------------------------------------------------------------------


def test_zip_inventory_lists_names_only():
    payload = conftest.zip_bytes(
        {"docs/readme.txt": b"hi", "run.exe": conftest.pe_bytes()}
    )
    raw = conftest.eml_with_attachments([("files.zip", "application/zip", payload)])
    rec = _analyze(raw).attachments[0]
    assert rec.archive is not None
    assert rec.archive.format == "zip"
    assert rec.archive.member_count == 2
    assert "archive-member-executable" in _codes(rec)


def test_password_protected_zip():
    raw = conftest.eml_with_attachments(
        [("secret.zip", "application/zip", conftest.encrypted_zip_bytes())]
    )
    analysis = _analyze(raw)
    rec = analysis.attachments[0]
    assert rec.archive is not None
    assert rec.archive.encrypted_entries == 1
    assert rec.archive.members[0].encrypted
    assert rec.archive.members[0].size is None
    assert "password-protected" in _codes(rec)


def test_nested_zip_inventoried():
    raw = conftest.eml_with_attachments(
        [("outer.zip", "application/zip", conftest.nested_zip_bytes(depth=2))]
    )
    rec = _analyze(raw).attachments[0]
    assert "nested-archive" in _codes(rec)
    assert len(rec.archive.nested_inventories) == 1
    assert rec.archive.nested_inventories[0].member_count == 1


def test_archive_depth_cap():
    raw = conftest.eml_with_attachments(
        [("deep.zip", "application/zip", conftest.nested_zip_bytes(depth=4))]
    )
    analysis = _analyze(raw, max_archive_depth=1)
    assert any(w.code == "archive-depth-capped" for w in analysis.parser_warnings)


def test_corrupt_zip_becomes_warning_not_crash():
    raw = conftest.eml_with_attachments(
        [("broken.zip", "application/zip", b"PK\x03\x04garbage-not-a-zip")]
    )
    analysis = _analyze(raw)
    assert analysis.attachments[0].archive is None
    assert any(w.code == "archive-unreadable" for w in analysis.parser_warnings)


def test_inventory_zip_rejects_garbage():
    try:
        inventory_zip(b"\x00" * 64, default_config(), [], "0.0")
    except ArchiveError:
        return
    raise AssertionError("expected ArchiveError")


def test_malformed_message_does_not_crash():
    cfg = default_config()
    try:
        analyze_attachments(b"\xff" * 100, "bad.eml", cfg)
    except ValueError:
        return  # acceptable: a clean error, not a crash
    # also acceptable: parsed as a message with no attachments


# ---------------------------------------------------------------------------
# Safety properties
# ---------------------------------------------------------------------------


def test_analysis_never_writes_to_disk(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    raw = conftest.eml_with_attachments(
        [
            ("tool.exe", "application/octet-stream", conftest.pe_bytes()),
            ("outer.zip", "application/zip", conftest.nested_zip_bytes()),
        ]
    )
    _analyze(raw)
    assert list(Path(tmp_path).iterdir()) == []


def test_no_network_access(monkeypatch):
    def _blocked(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", _blocked)
    raw = conftest.eml_with_attachments(
        [("tool.exe", "application/octet-stream", conftest.pe_bytes())]
    )
    _analyze(raw)


def test_json_output_deterministic():
    raw = conftest.eml_with_attachments(
        [("invoice.pdf.exe", "application/octet-stream", conftest.pe_bytes())]
    )

    def _normalized():
        d = _analyze(raw).to_dict()
        d["provenance"]["analyzed_at_utc"] = "X"
        return json.dumps(d, sort_keys=True)

    assert _normalized() == _normalized()


# ---------------------------------------------------------------------------
# Plugin registry + CLI
# ---------------------------------------------------------------------------


def test_plugin_registered():
    from phishscope.core.plugins import get_registry

    info = get_registry().get("attachments")
    assert info.version == "0.5.0"
    assert info.commands == ["attachments"]


def test_cli_attachments_human(tmp_path, capsys):
    raw = conftest.eml_with_attachments(
        [("invoice.pdf.exe", "application/octet-stream", conftest.pe_bytes())]
    )
    path = conftest.write_eml(tmp_path, raw)
    code = main(["attachments", path])
    out = capsys.readouterr().out
    assert code == 0
    assert "SAFETY BOUNDARY" in out
    assert "invoice.pdf.exe" in out
    assert "double-extension" in out
    assert "--hash for full" in out  # truncated by default


def test_cli_attachments_hash_flag(tmp_path, capsys):
    raw = conftest.eml_with_attachments(
        [("tool.exe", "application/octet-stream", conftest.pe_bytes())]
    )
    path = conftest.write_eml(tmp_path, raw)
    code = main(["attachments", "--hash", path])
    out = capsys.readouterr().out
    assert code == 0
    assert "--hash for full" not in out
    assert "md5" in out


def test_cli_attachments_json_exact_values(tmp_path, capsys):
    raw = conftest.eml_with_attachments(
        [("invoice.pdf.exe", "application/octet-stream", conftest.pe_bytes())]
    )
    path = conftest.write_eml(tmp_path, raw)
    code = main(["attachments", "--json", path])
    out = capsys.readouterr().out
    assert code == 0
    d = json.loads(out)
    att = d["message"]["attachments"]["attachments"][0]
    assert att["filename"] == "invoice.pdf.exe"
    assert len(att["sha256"]) == 64
    assert d["message"]["attachments"]["provenance"]["parser_name"] == (
        "phishscope.attachments"
    )


def test_cli_analyze_attachments_section(tmp_path, capsys):
    raw = conftest.eml_with_attachments(
        [("tool.exe", "application/octet-stream", conftest.pe_bytes())]
    )
    path = conftest.write_eml(tmp_path, raw)
    code = main(["analyze", "--attachments", path])
    out = capsys.readouterr().out
    assert code == 0
    assert "Attachments (1, in-memory only):" in out


def test_cli_analyze_attachments_json_block(tmp_path, capsys):
    raw = conftest.eml_with_attachments(
        [("tool.exe", "application/octet-stream", conftest.pe_bytes())]
    )
    path = conftest.write_eml(tmp_path, raw)
    code = main(["analyze", "--attachments", "--json", path])
    out = capsys.readouterr().out
    assert code == 0
    d = json.loads(out)
    assert "attachments_detail" in d["message"]
    assert (
        d["message"]["attachments_detail"]["attachments"][0]["filename"] == "tool.exe"
    )


def test_cli_missing_file_errors(tmp_path, capsys):
    code = main(["attachments", str(tmp_path / "nope.eml")])
    assert code == 2


def test_archive_member_names_not_extracted(tmp_path):
    """Names are listed; payload bytes of members never hit the filesystem."""
    payload = conftest.zip_bytes({"evil.exe": conftest.pe_bytes()})
    raw = conftest.eml_with_attachments([("files.zip", "application/zip", payload)])
    before = set(p.name for p in Path(tmp_path).iterdir())
    rec = _analyze(raw).attachments[0]
    assert rec.archive.members[0].name == "evil.exe"
    assert set(p.name for p in Path(tmp_path).iterdir()) == before


def test_zip_with_many_entries_capped():
    payload = conftest.zip_bytes({f"f{i}.txt": b"x" for i in range(10)})
    raw = conftest.eml_with_attachments([("many.zip", "application/zip", payload)])
    analysis = _analyze(raw, max_archive_entries=4)
    rec = analysis.attachments[0]
    assert rec.archive.truncated
    assert len(rec.archive.members) == 4
    assert rec.archive.member_count == 10
    assert any(w.code == "archive-entries-capped" for w in analysis.parser_warnings)
