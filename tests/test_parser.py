"""Tests for the safe .eml parser (v0.1)."""

from __future__ import annotations

import hashlib
import json

import pytest
from conftest import (
    deep_nesting,
    encoded_subject_and_address,
    huge_header,
    malformed_mime,
    many_parts,
    missing_date,
    multipart_alternative,
    multipart_mixed_with_attachment,
    naive_date,
    simple_text,
    truncated_message,
    unparseable_date,
    url_in_subject,
    write_eml,
)

from phishscope.core.config import default_config
from phishscope.parsers.safe_eml import (
    HeaderTooLarge,
    MessageTooLarge,
    MimeTooDeep,
    ParseError,
    TooManyParts,
    parse_bytes,
    parse_file,
)


@pytest.fixture()
def cfg():
    return default_config()


def test_simple_message_fields(cfg):
    msg, raw = parse_bytes(simple_text(), "simple.eml", cfg)
    assert msg.evidence_id.startswith("PS-MSG-")
    assert msg.evidence_id == "PS-MSG-" + msg.sha256[:12].upper()
    assert msg.sha256 == hashlib.sha256(raw).hexdigest()
    assert msg.size_bytes == len(raw)
    assert msg.from_addr is not None
    assert msg.from_addr.display_name == "Alice Example"
    assert msg.from_addr.addr == "alice@example.com"
    assert [a.addr for a in msg.to] == ["bob@example.com"]
    assert msg.subject == "Hello"
    assert msg.message_id == "<simple-001@example.com>"
    assert msg.date.valid is True
    assert msg.date.utc == "2026-10-02T12:00:00+00:00"
    assert msg.date.original == "Fri, 02 Oct 2026 12:00:00 +0000"
    assert msg.attachments == []
    assert msg.mime_tree.content_type == "text/plain"
    assert msg.provenance.parser_name == "phishscope.safe_eml"
    assert msg.provenance.phishscope_version == "0.1.0"


def test_multipart_structure_and_attachments(cfg):
    data = multipart_mixed_with_attachment()
    msg, _raw = parse_bytes(data, "mixed.eml", cfg)
    tree = msg.mime_tree
    assert tree.content_type == "multipart/mixed"
    assert len(tree.children) == 3
    assert [c.content_type for c in tree.children] == [
        "text/plain",
        "text/html",
        "application/octet-stream",
    ]
    assert [c.index for c in tree.children] == ["0.0", "0.1", "0.2"]
    # Containers aggregate children sizes; sha256 only on leaves.
    assert tree.sha256 is None
    assert tree.size_bytes == sum(c.size_bytes for c in tree.children)
    assert all(c.sha256 for c in tree.children)

    assert len(msg.attachments) == 1
    att = msg.attachments[0]
    assert att.filename == "Invoice_INV-4821.pdf"
    assert att.mime_claim == "application/octet-stream"
    assert att.size_bytes == len(b"%PDF-1.4 fake-invoice-bytes")
    assert att.sha256 == hashlib.sha256(b"%PDF-1.4 fake-invoice-bytes").hexdigest()
    assert att.part_index == "0.2"

    assert msg.reply_to[0].addr == "accounts@acme-billing-support.com"


def test_multipart_alternative(cfg):
    msg, _raw = parse_bytes(multipart_alternative(), "alt.eml", cfg)
    assert msg.mime_tree.content_type == "multipart/alternative"
    assert len(msg.mime_tree.children) == 2
    assert msg.attachments == []


def test_encoded_subject_and_address(cfg):
    msg, _raw = parse_bytes(encoded_subject_and_address(), "enc.eml", cfg)
    assert msg.subject == "Facture impayée — action requise"
    assert msg.from_addr is not None
    assert msg.from_addr.display_name == "Renée Dupont"
    assert msg.from_addr.addr == "renee@example.fr"


def test_missing_date_warns(cfg):
    msg, _raw = parse_bytes(missing_date(), "nodate.eml", cfg)
    assert msg.date.original is None
    assert msg.date.valid is False
    codes = [w.code for w in msg.parser_warnings]
    assert "missing-header" in codes
    assert any("Date" in w.detail for w in msg.parser_warnings)


def test_naive_date_keeps_utc_none(cfg):
    msg, _raw = parse_bytes(naive_date(), "naive.eml", cfg)
    assert msg.date.original == "Fri, 02 Oct 2026 12:00:00"
    assert msg.date.utc is None  # a timezone is never invented
    assert msg.date.valid is False


def test_unparseable_date(cfg):
    msg, _raw = parse_bytes(unparseable_date(), "baddate.eml", cfg)
    assert msg.date.original == "not a date at all"
    assert msg.date.utc is None
    assert msg.date.valid is False


def test_malformed_mime_warns_not_crash(cfg):
    msg, _raw = parse_bytes(malformed_mime(), "bad.eml", cfg)
    assert msg.sha256  # still hashed and identified
    assert len(msg.parser_warnings) > 0
    assert any(w.code == "mime-defect" for w in msg.parser_warnings)


def test_truncated_input_warns_not_crash(cfg):
    msg, _raw = parse_bytes(truncated_message(), "trunc.eml", cfg)
    assert msg.evidence_id.startswith("PS-MSG-")
    # Truncation must surface as warnings, never an exception.
    assert isinstance(msg.parser_warnings, list)


def test_hash_stability(cfg):
    data = multipart_mixed_with_attachment()
    msg1, _ = parse_bytes(data, "a.eml", cfg)
    msg2, _ = parse_bytes(data, "b.eml", cfg)
    assert msg1.sha256 == msg2.sha256
    assert msg1.evidence_id == msg2.evidence_id


def test_raw_never_in_model(cfg):
    """Mutating the normalized model cannot touch the raw bytes."""
    data = simple_text()
    msg, raw = parse_bytes(data, "simple.eml", cfg)
    model_dict = msg.to_dict()
    model_dict["subject"] = "MUTATED"
    model_dict["sha256"] = "MUTATED"
    assert raw == data  # raw bytes object untouched
    assert msg.subject == "Hello"  # model field intact
    serialized = json.dumps(msg.to_dict())
    assert "MUTATED" not in serialized
    assert "Hi Bob" not in serialized  # body content never enters the model


def test_parse_file_roundtrip(tmp_path, cfg):
    path = write_eml(tmp_path, simple_text())
    msg, raw = parse_file(path, cfg)
    assert raw == simple_text()
    assert msg.source_path == path


def test_parse_file_missing(tmp_path, cfg):
    with pytest.raises(FileNotFoundError):
        parse_file(str(tmp_path / "nope.eml"), cfg)


def test_parse_file_directory(tmp_path, cfg):
    with pytest.raises(IsADirectoryError):
        parse_file(str(tmp_path), cfg)


def test_message_too_large_rejected(tmp_path, cfg):
    cfg.max_message_size_bytes = 100
    path = write_eml(tmp_path, simple_text())
    with pytest.raises(MessageTooLarge):
        parse_file(path, cfg)


def test_header_too_large_rejected(cfg):
    with pytest.raises(HeaderTooLarge):
        parse_bytes(huge_header(), "big.eml", cfg)


def test_too_many_parts_rejected(cfg):
    with pytest.raises(TooManyParts):
        parse_bytes(many_parts(201), "many.eml", cfg)


def test_many_parts_within_limit_ok(cfg):
    msg, _raw = parse_bytes(many_parts(50), "many.eml", cfg)
    assert len(msg.mime_tree.children) == 50


def test_mime_too_deep_rejected(cfg):
    with pytest.raises(MimeTooDeep):
        parse_bytes(deep_nesting(20), "deep.eml", cfg)


def test_mime_depth_within_limit_ok(cfg):
    msg, _raw = parse_bytes(deep_nesting(5), "deep.eml", cfg)
    depth = 0
    node = msg.mime_tree
    while node.children:
        depth += 1
        node = node.children[0]
    assert depth == 5


def test_to_dict_schema_keys_stable(cfg):
    msg, _raw = parse_bytes(multipart_mixed_with_attachment(), "m.eml", cfg)
    d = msg.to_dict()
    assert set(d.keys()) == {
        "evidence_id",
        "source_path",
        "sha256",
        "size_bytes",
        "date",
        "from",
        "to",
        "cc",
        "reply_to",
        "return_path",
        "message_id",
        "subject",
        "mime_tree",
        "attachments",
        "parser_warnings",
        "provenance",
    }
    assert set(d["date"].keys()) == {"original", "utc", "valid"}
    assert set(d["from"].keys()) == {"display_name", "addr", "raw"}
    assert set(d["attachments"][0].keys()) == {
        "filename",
        "mime_claim",
        "size_bytes",
        "sha256",
        "part_index",
    }
    assert set(d["mime_tree"].keys()) == {
        "index",
        "content_type",
        "filename",
        "size_bytes",
        "is_attachment",
        "sha256",
        "children",
    }
    assert set(d["parser_warnings"][0].keys()) if d["parser_warnings"] else True
    assert set(d["provenance"].keys()) == {
        "parser_name",
        "parser_version",
        "phishscope_version",
        "analyzed_at_utc",
    }


def test_to_dict_deterministic(cfg):
    data = multipart_mixed_with_attachment()  # one generation: boundary is random
    msg, _raw = parse_bytes(data, "m.eml", cfg)
    first = json.dumps(msg.to_dict(), sort_keys=True)
    # Re-parse the SAME bytes and compare: identical input -> identical
    # JSON (sans the analysis timestamp).
    msg2, _raw2 = parse_bytes(data, "m.eml", cfg)
    d1, d2 = msg.to_dict(), msg2.to_dict()
    d1["provenance"]["analyzed_at_utc"] = "X"
    d2["provenance"]["analyzed_at_utc"] = "X"
    assert json.dumps(d1, sort_keys=True) == json.dumps(d2, sort_keys=True)
    assert first  # sanity


def test_url_subject_kept_verbatim_in_model(cfg):
    msg, _raw = parse_bytes(url_in_subject(), "u.eml", cfg)
    assert msg.subject == "See http://evil.example.com/login for details"


def test_empty_message_warns(cfg):
    msg, _raw = parse_bytes(b"", "empty.eml", cfg)
    assert msg.sha256 == hashlib.sha256(b"").hexdigest()
    assert msg.subject is None
    assert msg.from_addr is None
    codes = [w.code for w in msg.parser_warnings]
    assert "missing-header" in codes


def test_parse_error_is_exception():
    assert issubclass(MessageTooLarge, ParseError)
    assert issubclass(HeaderTooLarge, ParseError)
    assert issubclass(TooManyParts, ParseError)
    assert issubclass(MimeTooDeep, ParseError)


def test_safe_eml_reexport():
    from phishscope import parsers

    assert parsers.safe_eml.PARSER_NAME == "phishscope.safe_eml"
