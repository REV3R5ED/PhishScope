"""Tests for PhishScope v0.2 header & Received-chain forensics.

Every fixture is synthetic (built in ``conftest`` with the stdlib or
hand-crafted byte strings) — no real mailboxes, no network, fully
deterministic.
"""

from __future__ import annotations

import json
import socket

from conftest import (
    direct_send_eml,
    ipv6_hop_eml,
    mailing_list_eml,
    malformed_received_eml,
    minimal_headers_eml,
    private_ip_hop_eml,
    timestamp_inversion_eml,
    write_eml,
    x_originating_ip_eml,
)

import phishscope
from phishscope.cli.main import main
from phishscope.core.config import default_config
from phishscope.headers.analysis import analyze_headers
from phishscope.headers.received import parse_received_chain, parse_received_value


def run(argv: list[str]) -> int:
    return main(argv)


def analyze(data: bytes, tmp_path, name: str = "m.eml"):
    path = write_eml(tmp_path, data, name)
    raw = open(path, "rb").read()
    return analyze_headers(raw, path, default_config())


def codes(analysis) -> list[str]:
    return [o.code for o in analysis.observations]


# ---------------------------------------------------------------------------
# Received parsing correctness
# ---------------------------------------------------------------------------


def test_each_field_lands_in_its_slot(tmp_path):
    a = analyze(direct_send_eml(), tmp_path)
    assert len(a.received) == 2
    oldest, newest = a.received
    # Hop 0 = oldest (last Received header in the raw message).
    assert oldest.position == 0
    assert oldest.from_host == "client.example.net"
    assert oldest.from_ip == "192.0.2.25"
    assert oldest.by_host == "mail.example.net"
    assert oldest.by_ip is None
    assert oldest.with_protocol == "ESMTP"
    assert oldest.hop_id == "BBB222"
    assert oldest.timestamp_valid
    assert oldest.timestamp_utc == "2026-10-02T14:30:05+00:00"
    # Hop 1 = newest delivery hop.
    assert newest.position == 1
    assert newest.from_host == "mail.example.net"
    assert newest.from_ip == "192.0.2.10"
    assert newest.by_host == "mx.example.com"
    assert newest.with_protocol == "ESMTPS"
    assert newest.hop_id == "AAA111"
    assert newest.timestamp_utc == "2026-10-02T14:31:00+00:00"


def test_hop_ordering_oldest_to_newest(tmp_path):
    a = analyze(direct_send_eml(), tmp_path)
    positions = [h.position for h in a.received]
    assert positions == [0, 1]
    stamps = [h.timestamp_utc for h in a.received]
    assert stamps == sorted(stamps)


def test_raw_value_always_preserved(tmp_path):
    a = analyze(direct_send_eml(), tmp_path)
    assert "by mail.example.net with ESMTP id BBB222" in a.received[0].raw


def test_ipv6_bracketed_literals(tmp_path):
    a = analyze(ipv6_hop_eml(), tmp_path)
    assert len(a.received) == 1
    hop = a.received[0]
    assert hop.from_ip == "2001:db8::10"
    assert hop.by_ip == "2001:db8::1"
    assert hop.with_protocol == "ESMTPS"


def test_no_received_headers(tmp_path):
    a = analyze(minimal_headers_eml(), tmp_path)
    assert a.received == []
    assert "hop-count" in codes(a)
    assert "no-received-headers" in codes(a)
    assert a.parser_warnings == []


# ---------------------------------------------------------------------------
# Observations (facts, not verdicts)
# ---------------------------------------------------------------------------


def test_timestamp_inversion_is_an_observation(tmp_path):
    a = analyze(timestamp_inversion_eml(), tmp_path)
    inversions = [o for o in a.observations if o.code == "timestamp-inversion"]
    assert len(inversions) == 1
    inv = inversions[0]
    assert inv.basis["hop"] == 1
    assert inv.basis["previous_hop"] == 0
    assert "earlier than hop 0" in inv.detail
    # Observation carries evidence, not a verdict.
    assert "phishing" not in inv.detail.lower()


def test_private_ip_hop_observation(tmp_path):
    a = analyze(private_ip_hop_eml(), tmp_path)
    priv = [o for o in a.observations if o.code == "private-ip-hop"]
    assert priv, "RFC 1918 hop must be observed"
    assert any(o.basis["ip"] == "192.168.1.10" for o in priv)


def test_documentation_ranges_are_not_flagged_private(tmp_path):
    """TEST-NET addresses are public placeholders, not internal infra."""
    a = analyze(direct_send_eml(), tmp_path)  # 192.0.2.x throughout
    assert "private-ip-hop" not in codes(a)


def test_unverifiable_from_without_ip(tmp_path):
    raw = (
        b"Received: from shady-relay by mx.example.com;\r\n"
        b"\tFri, 02 Oct 2026 14:31:00 +0000\r\n"
        b"From: a@example.com\r\nTo: b@example.com\r\n"
        b"Subject: x\r\nDate: Fri, 02 Oct 2026 14:30:00 +0000\r\n"
        b"Message-ID: <u1@example.com>\r\n\r\nbody\r\n"
    )
    a = analyze(raw, tmp_path)
    unver = [o for o in a.observations if o.code == "unverifiable-from"]
    assert len(unver) == 1
    assert unver[0].basis["from_host"] == "shady-relay"
    assert "no DNS performed" in unver[0].detail


def test_missing_timestamp_observed(tmp_path):
    raw = (
        b"Received: from a.example by b.example with SMTP id 1\r\n"
        b"From: a@example.com\r\nTo: b@example.com\r\n"
        b"Subject: x\r\nDate: Fri, 02 Oct 2026 14:30:00 +0000\r\n"
        b"Message-ID: <u2@example.com>\r\n\r\nbody\r\n"
    )
    a = analyze(raw, tmp_path)
    assert len(a.received) == 1
    hop = a.received[0]
    assert not hop.timestamp_valid
    assert hop.timestamp_utc is None
    assert "missing-timestamp" in codes(a)
    assert any(w.code == "received-no-timestamp" for w in a.parser_warnings)


# ---------------------------------------------------------------------------
# Malformed input: warnings, never crashes
# ---------------------------------------------------------------------------


def test_malformed_received_never_crashes(tmp_path):
    a = analyze(malformed_received_eml(), tmp_path)
    assert len(a.received) == 3  # one hop per header, even garbage ones
    assert a.parser_warnings, "malformed lines must be recorded"
    warn_codes = {w.code for w in a.parser_warnings}
    assert warn_codes & {"received-no-timestamp", "received-unparseable"}


def test_parse_received_value_unit():
    hop, warnings = parse_received_value("from a ([1.2.3.4]) by b with SMTP id z;", 0)
    assert hop.from_host == "a"
    assert hop.from_ip == "1.2.3.4"
    assert hop.by_host == "b"
    assert hop.with_protocol == "SMTP"
    assert hop.hop_id == "z"
    assert not hop.timestamp_valid
    assert any(w.code == "received-no-timestamp" for w in warnings)


def test_parse_received_chain_empty():
    hops, warnings = parse_received_chain(b"From: a@b.c\r\n\r\nbody\r\n")
    assert hops == [] and warnings == []


# ---------------------------------------------------------------------------
# Header normalization
# ---------------------------------------------------------------------------


def test_mailing_list_headers(tmp_path):
    a = analyze(mailing_list_eml(), tmp_path)
    assert len(a.received) == 3
    assert a.list_headers["list-id"] == "<announce.example.org>"
    assert a.list_headers["list-unsubscribe"] == "<mailto:leave@example.org>"
    assert a.x_mailer == "ListManager 9.1"


def test_x_originating_ip_observed(tmp_path):
    a = analyze(x_originating_ip_eml(), tmp_path)
    assert a.x_originating_ip == "[203.0.113.200]"
    assert a.x_mailer == "WebMail 3.0"
    assert a.user_agent == "WebMail/3.0"
    claims = [o for o in a.observations if o.code == "originating-ip-claim"]
    assert len(claims) == 1
    assert "not verified" in claims[0].detail


def test_return_path_message_id_date(tmp_path):
    a = analyze(direct_send_eml(), tmp_path)
    assert a.return_path is not None and a.return_path.addr == "bounce@example.net"
    assert a.message_id == "<hdr-test@example.net>"
    assert a.date.valid and a.date.utc == "2026-10-02T14:30:00+00:00"
    assert a.mime_version == "1.0"
    assert a.top_content_type == "text/plain"


def test_provenance_on_analysis(tmp_path):
    a = analyze(direct_send_eml(), tmp_path)
    p = a.provenance
    assert p.parser_name == "phishscope.headers"
    assert p.parser_version == "0.2.0"
    assert p.phishscope_version == phishscope.__version__
    assert p.analyzed_at_utc
    assert a.evidence_id == "PS-MSG-" + a.sha256[:12].upper()


def test_analysis_to_dict_deterministic(tmp_path):
    a1 = analyze(direct_send_eml(), tmp_path, "a.eml")
    a2 = analyze(direct_send_eml(), tmp_path, "b.eml")
    d1, d2 = a1.to_dict(), a2.to_dict()
    for key in ("received", "observations", "list_headers"):
        assert d1[key] == d2[key]


# ---------------------------------------------------------------------------
# CLI: hops
# ---------------------------------------------------------------------------


def test_hops_human(tmp_path, capsys):
    path = write_eml(tmp_path, direct_send_eml())
    assert run(["hops", path]) == 0
    out = capsys.readouterr().out
    assert "oldest → newest" in out
    assert "[hop 0]" in out and "[hop 1]" in out
    assert "client.example.net [192.0.2.25]" in out
    # Oldest hop appears before the newest in the output.
    assert out.index("[hop 0]") < out.index("[hop 1]")


def test_hops_json(tmp_path, capsys):
    path = write_eml(tmp_path, direct_send_eml())
    assert run(["hops", path, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "hops"
    assert payload["status"] == "ok"
    headers = payload["message"]["headers"]
    assert len(headers["received"]) == 2
    assert headers["received"][0]["from_ip"] == "192.0.2.25"
    assert headers["provenance"]["parser_name"] == "phishscope.headers"


def test_hops_warnings_exit_code(tmp_path, capsys):
    path = write_eml(tmp_path, malformed_received_eml())
    assert run(["hops", path]) == 1
    out = capsys.readouterr().out
    assert "Header parser warnings" in out


def test_hops_error_exit_code(tmp_path, capsys):
    assert run(["hops", "/nonexistent/m.eml"]) == 2
    assert "error" in capsys.readouterr().err


def test_hops_human_shows_observations(tmp_path, capsys):
    path = write_eml(tmp_path, private_ip_hop_eml())
    # Observations are facts, not warnings: exit 0.
    assert run(["hops", path]) == 0
    out = capsys.readouterr().out
    assert "private-ip-hop" in out


# ---------------------------------------------------------------------------
# CLI: analyze --headers
# ---------------------------------------------------------------------------


def test_analyze_headers_flag_human(tmp_path, capsys):
    path = write_eml(tmp_path, direct_send_eml())
    assert run(["analyze", path, "--headers"]) == 0
    out = capsys.readouterr().out
    assert "Routing headers:" in out
    assert "Received chain (2 hops, oldest → newest):" in out
    assert "Observations" in out


def test_analyze_headers_flag_json(tmp_path, capsys):
    path = write_eml(tmp_path, direct_send_eml())
    assert run(["analyze", path, "--headers", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "headers" in payload["message"]
    assert len(payload["message"]["headers"]["received"]) == 2


def test_analyze_without_headers_flag_has_no_headers_block(tmp_path, capsys):
    path = write_eml(tmp_path, direct_send_eml())
    assert run(["analyze", path, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "headers" not in payload["message"]


def test_analyze_headers_warnings_exit_code(tmp_path, capsys):
    path = write_eml(tmp_path, malformed_received_eml())
    assert run(["analyze", path, "--headers"]) == 1


# ---------------------------------------------------------------------------
# Safety: no network, ever
# ---------------------------------------------------------------------------


def test_no_network_during_header_analysis(tmp_path, monkeypatch):
    def _blocked(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
    monkeypatch.setattr(socket, "gethostbyname", _blocked)
    a = analyze(direct_send_eml(), tmp_path)
    assert len(a.received) == 2


def test_no_network_in_hops_cli(tmp_path, capsys, monkeypatch):
    def _blocked(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", _blocked)
    path = write_eml(tmp_path, mailing_list_eml())
    assert run(["hops", path]) == 0
    assert "[hop 2]" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Plugin registry
# ---------------------------------------------------------------------------


def test_headers_module_registered():
    from phishscope.core.plugins import get_registry

    info = get_registry().get("headers")
    assert info.version == "0.2.0"
    assert "hops" in info.commands
