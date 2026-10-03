"""Safety tests: bounds, hostile input, and the no-network guarantee."""

from __future__ import annotations

import socket

from conftest import (
    deep_nesting,
    huge_header,
    many_parts,
    multipart_mixed_with_attachment,
    simple_text,
    write_eml,
)

from phishscope.cli.main import main


def test_no_network_access(tmp_path, monkeypatch):
    """PhishScope must never open a socket, even implicitly."""

    def _blocked(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
    path = write_eml(tmp_path, multipart_mixed_with_attachment())
    assert main(["analyze", path, "--json"]) == 0
    assert main(["overview", path]) == 0


def test_oversize_rejected_exit_2(tmp_path, capsys, monkeypatch):
    from phishscope.core import config as config_mod

    monkeypatch.setattr(config_mod, "default_config", lambda: _small_config(config_mod))
    path = write_eml(tmp_path, simple_text())
    assert main(["analyze", path]) == 2
    assert "safety limit" in capsys.readouterr().err


def _small_config(config_mod):
    cfg = config_mod.AppConfig()
    cfg.max_message_size_bytes = 10
    return cfg


def test_header_limit_rejected_exit_2(tmp_path, capsys):
    path = write_eml(tmp_path, huge_header())
    assert main(["analyze", path]) == 2
    assert "safety limit" in capsys.readouterr().err


def test_too_many_parts_rejected_exit_2(tmp_path, capsys):
    path = write_eml(tmp_path, many_parts(250))
    assert main(["analyze", path]) == 2
    assert "safety limit" in capsys.readouterr().err


def test_deep_nesting_rejected_exit_2(tmp_path, capsys):
    path = write_eml(tmp_path, deep_nesting(25))
    assert main(["analyze", path]) == 2
    assert "safety limit" in capsys.readouterr().err


def test_binary_garbage_does_not_crash(tmp_path):
    path = write_eml(tmp_path, b"\x00\x01\x02\xff\xfe" * 100)
    code = main(["analyze", path])
    assert code in (0, 1)  # parsed or warned — never a crash (exit 2 is error)


def test_null_bytes_in_headers(tmp_path):
    data = b"From: a\x00b@example.com\r\nSubject: x\r\n\r\nbody\r\n"
    path = write_eml(tmp_path, data)
    code = main(["analyze", path])
    assert code in (0, 1)


def test_plugin_registry_has_core():
    from phishscope.core.plugins import get_registry

    registry = get_registry()
    assert "core" in registry.names()
    info = registry.get("core")
    assert info.version == "0.1.0"
    assert "analyze" in info.commands
