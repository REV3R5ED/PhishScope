"""Tests for core framework pieces (config, hashing, results, plugins)."""

from __future__ import annotations

import json

import pytest
from conftest import simple_text, write_eml

from phishscope.core import plugins
from phishscope.core.config import AppConfig, ConfigError, default_config
from phishscope.core.hashing import HashingError, hash_file, sha256_bytes
from phishscope.core.logging import audit_log, utc_now_iso
from phishscope.core.models import evidence_id_for
from phishscope.core.results import (
    EXIT_ERROR,
    EXIT_FINDINGS,
    EXIT_OK,
    Finding,
    Result,
    exit_code_for,
)


def test_default_config_bounds():
    cfg = default_config()
    assert cfg.max_message_size_bytes == 25 * 1024 * 1024
    assert cfg.max_mime_parts == 200
    assert cfg.max_header_size_bytes == 1024 * 1024
    assert cfg.max_mime_depth == 16
    assert isinstance(cfg, AppConfig)
    assert issubclass(ConfigError, Exception)


def test_sha256_bytes():
    assert sha256_bytes(b"abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_hash_file(tmp_path):
    path = write_eml(tmp_path, simple_text())
    size, digest = hash_file(path)
    assert size == len(simple_text())
    assert digest == sha256_bytes(simple_text())


def test_hash_file_not_a_file(tmp_path):
    with pytest.raises(HashingError):
        hash_file(str(tmp_path / "missing.eml"))


def test_utc_now_iso():
    assert utc_now_iso().endswith("+00:00")


def test_audit_log_best_effort(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHCOPE_STATE_DIR", str(tmp_path / "s"))
    audit_log({"command": ["test"], "exit": 0})
    lines = (tmp_path / "s" / "audit.log").read_text().splitlines()
    assert json.loads(lines[0])["command"] == ["test"]


def test_evidence_id_format():
    eid = evidence_id_for("ab" * 32)
    assert eid == "PS-MSG-" + "AB" * 6


def test_exit_codes():
    ok = Result(status="ok", command="analyze")
    assert exit_code_for(ok) == EXIT_OK
    warned = Result(status="ok", command="analyze")
    assert exit_code_for(warned, warnings_present=True) == EXIT_FINDINGS
    flagged = Result(
        status="ok",
        command="analyze",
        findings=[Finding("x", "low", 50, "d")],
    )
    assert exit_code_for(flagged) == EXIT_FINDINGS
    err = Result(status="error", command="analyze", errors=["boom"])
    assert exit_code_for(err) == EXIT_ERROR


def test_result_envelope():
    result = Result(
        status="ok",
        command="overview",
        findings=[Finding("r", "info", 90, "detail", {"k": "v"})],
    )
    d = result.to_dict()
    assert d["tool"] == "phishscope"
    assert d["findings"][0]["rule_id"] == "r"
    assert d["findings"][0]["evidence"] == {"k": "v"}


def test_plugin_registry_duplicate_rejected():
    with pytest.raises(ValueError):
        plugins.register(plugins.ModuleInfo(name="core", description="dup"))


def test_plugin_registry_unknown():
    with pytest.raises(KeyError):
        plugins.get_registry().get("no-such-module")
