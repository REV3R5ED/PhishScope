"""Tests for the PhishScope CLI (v0.1: analyze, overview)."""

from __future__ import annotations

import json

from conftest import (
    malformed_mime,
    multipart_mixed_with_attachment,
    simple_text,
    url_in_subject,
    write_eml,
)

import phishscope
from phishscope.cli.main import RAW_SAFETY_BANNER, defang_text, main, truncate


def run(argv: list[str]):
    return main(argv)


def test_version(capsys):
    assert run(["--version"]) == 0
    out = capsys.readouterr().out
    assert phishscope.__version__ in out


def test_analyze_human(tmp_path, capsys):
    path = write_eml(tmp_path, simple_text())
    assert run(["analyze", path]) == 0
    out = capsys.readouterr().out
    assert "PS-MSG-" in out
    assert "alice@example.com" in out
    assert "Hello" in out


def test_analyze_json_schema(tmp_path, capsys):
    path = write_eml(tmp_path, simple_text())
    assert run(["analyze", path, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["tool"] == "phishscope"
    assert payload["version"] == phishscope.__version__
    assert payload["status"] == "ok"
    assert payload["command"] == "analyze"
    assert payload["errors"] == []
    message = payload["message"]
    assert message["evidence_id"].startswith("PS-MSG-")
    assert message["from"]["addr"] == "alice@example.com"


def test_analyze_json_keeps_exact_values(tmp_path, capsys):
    """--json is never defanged: tooling gets exact values."""
    path = write_eml(tmp_path, url_in_subject())
    assert run(["analyze", path, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "http://evil.example.com/login" in payload["message"]["subject"]


def test_analyze_human_defangs_urls(tmp_path, capsys):
    path = write_eml(tmp_path, url_in_subject())
    assert run(["analyze", path]) == 0
    out = capsys.readouterr().out
    assert "hxxp://evil[.]example[.]com/login" in out
    assert "http://evil.example.com" not in out


def test_overview_human(tmp_path, capsys):
    path = write_eml(tmp_path, multipart_mixed_with_attachment())
    assert run(["overview", path]) == 0
    out = capsys.readouterr().out
    assert "message overview" in out
    assert "Attachments: 1" in out
    assert "Invoice_INV-4821.pdf" in out


def test_overview_json(tmp_path, capsys):
    path = write_eml(tmp_path, simple_text())
    assert run(["overview", path, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "ok"
    assert payload["command"] == "overview"
    assert payload["message"]["subject"] == "Hello"


def test_overview_defangs(tmp_path, capsys):
    path = write_eml(tmp_path, url_in_subject())
    assert run(["overview", path]) == 0
    out = capsys.readouterr().out
    assert "hxxp://" in out


def test_warnings_exit_1(tmp_path, capsys):
    path = write_eml(tmp_path, malformed_mime())
    code = run(["analyze", path])
    assert code == 1
    out = capsys.readouterr().out
    assert "Parser warnings" in out


def test_missing_file_exit_2(tmp_path, capsys):
    code = run(["analyze", str(tmp_path / "nope.eml")])
    assert code == 2
    err = capsys.readouterr().err
    assert "no such file" in err


def test_show_raw_banner_and_verbatim(tmp_path, capsys):
    data = simple_text()
    path = write_eml(tmp_path, data)
    assert run(["analyze", path, "--show-raw"]) == 0
    out = capsys.readouterr().out
    assert RAW_SAFETY_BANNER.splitlines()[1] in out  # banner present
    assert "Hi Bob," in out  # raw body shown verbatim
    assert "SAFETY NOTICE" in out


def test_show_raw_never_in_json(tmp_path, capsys):
    path = write_eml(tmp_path, simple_text())
    assert run(["analyze", path, "--json", "--show-raw"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "Hi Bob," not in json.dumps(payload)


def test_error_json_envelope(tmp_path, capsys):
    code = run(["overview", str(tmp_path / "nope.eml"), "--json"])
    assert code == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "error"
    assert payload["message"] is None
    assert payload["errors"]


def test_defang_text_unit():
    assert defang_text("visit http://evil.example.com/a") == (
        "visit hxxp://evil[.]example[.]com/a"
    )
    assert defang_text("https://Example.COM/X") == "hxxps://Example[.]COM/X"
    assert defang_text("no urls here") == "no urls here"
    assert defang_text("a@b.com is not a url") == "a@b.com is not a url"


def test_truncate_unit():
    assert truncate("abc", 10) == "abc"
    short = truncate("x" * 300, 200)
    assert len(short) < 300 and "see --json" in short


def test_audit_log_written(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("PHISHCOPE_STATE_DIR", str(tmp_path / "state"))
    path = write_eml(tmp_path, simple_text())
    assert run(["analyze", path]) == 0
    audit = tmp_path / "state" / "audit.log"
    assert audit.exists()
    record = json.loads(audit.read_text().splitlines()[0])
    assert record["command"][0] == "analyze"
    assert record["exit"] == 0


def test_help_lists_commands(capsys):
    assert run(["--help"]) == 0
    out = capsys.readouterr().out
    assert "analyze" in out and "overview" in out
