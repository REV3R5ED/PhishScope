"""Tests for v0.3 authentication analysis (offline SPF/DKIM/DMARC)."""

from __future__ import annotations

import json
import socket

from conftest import (
    auth_all_pass_eml,
    auth_conflicting_eml,
    auth_dkim_none_eml,
    auth_malformed_eml,
    auth_misaligned_eml,
    auth_spf_fail_eml,
    simple_text,
    write_eml,
)

from phishscope.auth.analysis import (
    PARSER_NAME,
    PARSER_VERSION,
    analyze_auth,
)
from phishscope.auth.authentication_results import (
    known_result_token,
    parse_authentication_results,
)
from phishscope.auth.dkim import parse_dkim_signature
from phishscope.auth.received_spf import parse_received_spf
from phishscope.cli.main import main
from phishscope.core import config as config_mod


def _cfg():
    return config_mod.default_config()


def _analyze(data: bytes):
    return analyze_auth(data, "test.eml", _cfg())


def _obs_codes(analysis):
    return [o.code for o in analysis.observations]


# ---------------------------------------------------------------------------
# Authentication-Results parsing
# ---------------------------------------------------------------------------


def test_ar_all_pass_fields():
    analysis = _analyze(auth_all_pass_eml())
    by_method = {r.method: r for r in analysis.auth_results}
    assert set(by_method) == {"spf", "dkim", "dmarc"}
    spf = by_method["spf"]
    assert spf.result == "pass"
    assert spf.authserv_id == "mx.northwind.example"
    assert spf.properties["smtp.mailfrom"] == "bounce-9917@acme-invoices.net"
    assert spf.reason == "sender IP is 203.0.113.45"
    dkim = by_method["dkim"]
    assert dkim.result == "pass"
    assert dkim.properties["header.i"] == "@acme-invoices.net"
    dmarc = by_method["dmarc"]
    assert dmarc.result == "pass"
    assert dmarc.properties["header.from"] == "acme-invoices.net"


def test_ar_result_tokens_parsed_verbatim():
    for token in (
        "pass",
        "fail",
        "none",
        "neutral",
        "softfail",
        "temperror",
        "permerror",
        "policy",
    ):
        _authserv, results, warnings = parse_authentication_results(
            f"mx.example.com; spf={token} reason-here smtp.mailfrom=a@b.example"
        )
        assert not warnings
        assert len(results) == 1
        assert results[0].result == token
        assert known_result_token(token)


def test_ar_unknown_result_token_preserved():
    _authserv, results, _warnings = parse_authentication_results(
        "mx.example.com; spf=bogus-result smtp.mailfrom=a@b.example"
    )
    assert results[0].result == "bogus-result"
    assert not known_result_token("bogus-result")


def test_ar_multiple_headers_all_kept():
    analysis = _analyze(auth_conflicting_eml())
    assert len(analysis.auth_results) == 2
    ids = {r.authserv_id for r in analysis.auth_results}
    assert ids == {"mx.northwind.example", "gateway.example.org"}


def test_ar_conflicting_results_observed():
    analysis = _analyze(auth_conflicting_eml())
    assert "conflicting-auth-results" in _obs_codes(analysis)
    obs = next(o for o in analysis.observations if o.code == "conflicting-auth-results")
    assert obs.basis["method"] == "spf"
    assert set(obs.basis["results"]) == {"pass", "fail"}


def test_ar_malformed_warns_not_crash():
    analysis = _analyze(auth_malformed_eml())
    codes = [w.code for w in analysis.parser_warnings]
    assert "auth-results-no-clauses" in codes
    assert "auth-results-clause-no-equals" in codes
    # Analysis still completes with observations.
    assert analysis.observations


def test_ar_reason_with_semicolon_inside_parens():
    _authserv, results, warnings = parse_authentication_results(
        "mx.example.com; spf=fail (a;b) smtp.mailfrom=a@b.example"
    )
    assert not warnings
    assert len(results) == 1
    assert results[0].result == "fail"
    assert results[0].reason == "a;b"


# ---------------------------------------------------------------------------
# Received-SPF parsing
# ---------------------------------------------------------------------------


def test_received_spf_pass_fields():
    entry, warnings = parse_received_spf(
        "pass (mx.example.com: domain of a@b.example designates 1.2.3.4 "
        "as permitted sender) client-ip=1.2.3.4;"
    )
    assert not warnings
    assert entry is not None
    assert entry.result == "pass"
    assert "designates 1.2.3.4" in (entry.detail or "")


def test_received_spf_fail():
    analysis = _analyze(auth_spf_fail_eml())
    assert len(analysis.received_spf) == 1
    assert analysis.received_spf[0].result == "fail"
    assert "spf-fail" in _obs_codes(analysis)
    assert "received-spf-fail" in _obs_codes(analysis)


def test_received_spf_malformed():
    entry, warnings = parse_received_spf("")
    assert entry is None
    assert any(w.code == "received-spf-empty" for w in warnings)
    entry, warnings = parse_received_spf("(no result token here)")
    assert entry is None
    assert any(w.code == "received-spf-no-result" for w in warnings)


def test_spf_claim_disagreement_observed(tmp_path):
    data = (
        b"From: a@example.net\r\n"
        b"To: b@example.com\r\n"
        b"Subject: x\r\n"
        b"Date: Fri, 02 Oct 2026 12:00:00 +0000\r\n"
        b"Message-ID: <dis-1@example.net>\r\n"
        b"Authentication-Results: mx.example.com;\r\n"
        b"\tspf=fail smtp.mailfrom=a@example.net\r\n"
        b"Received-SPF: pass (mx.example.com: ok) client-ip=1.2.3.4;\r\n"
        b"\r\nbody\r\n"
    )
    analysis = _analyze(data)
    assert "spf-claim-disagreement" in _obs_codes(analysis)


# ---------------------------------------------------------------------------
# DKIM-Signature parsing
# ---------------------------------------------------------------------------


def test_dkim_signature_fields():
    sig, warnings = parse_dkim_signature(
        "v=1; a=rsa-sha256; c=relaxed/simple; d=acme-invoices.net; "
        "s=sel2026; t=1727874600; bh=QUJD; h=From:To:Subject; "
        "b=U0lHTkFUVVJF"
    )
    assert not warnings
    assert sig is not None
    assert sig.d == "acme-invoices.net"
    assert sig.s == "sel2026"
    assert sig.a == "rsa-sha256"
    assert sig.c == "relaxed/simple"
    assert sig.bh == "QUJD"
    assert sig.h == ["from", "to", "subject"]
    assert sig.other_tags["b"] == "U0lHTkFUVVJF"
    assert sig.other_tags["t"] == "1727874600"
    d = sig.to_dict()
    assert d["cryptographically_verified"] is False
    assert "offline" in d["verification_note"]


def test_dkim_signature_present_observed_not_verified():
    analysis = _analyze(auth_all_pass_eml())
    assert len(analysis.dkim_signatures) == 1
    assert "dkim-signature-present" in _obs_codes(analysis)
    obs = next(o for o in analysis.observations if o.code == "dkim-signature-present")
    assert "NOT cryptographically verified" in obs.detail
    assert obs.basis["d"] == "acme-invoices.net"


def test_dkim_signature_absent_observed():
    analysis = _analyze(auth_dkim_none_eml())
    assert analysis.dkim_signatures == []
    assert "dkim-signature-absent" in _obs_codes(analysis)


def test_dkim_missing_d_warns():
    sig, warnings = parse_dkim_signature("v=1; a=rsa-sha256; s=sel1")
    assert sig is not None
    assert sig.d is None
    assert any(w.code == "dkim-missing-d" for w in warnings)


def test_dkim_garbage_warns():
    sig, warnings = parse_dkim_signature("not-a-tag-list")
    assert sig is None
    assert any(w.code == "dkim-tag-no-equals" for w in warnings)


# ---------------------------------------------------------------------------
# Alignment observations
# ---------------------------------------------------------------------------


def test_alignment_aligned_all_pass():
    analysis = _analyze(auth_all_pass_eml())
    # From: sender@example.net in the shared fixture base; SPF/DKIM
    # claim acme-invoices.net -> both unaligned vs example.net.
    codes = _obs_codes(analysis)
    assert "spf-alignment-unaligned" in codes
    assert "dkim-alignment-unaligned" in codes


def test_alignment_aligned_when_domains_match():
    data = (
        b"From: Billing <billing@acme-invoices.net>\r\n"
        b"To: b@example.com\r\n"
        b"Subject: x\r\n"
        b"Date: Fri, 02 Oct 2026 12:00:00 +0000\r\n"
        b"Message-ID: <al-1@acme-invoices.net>\r\n"
        b"Authentication-Results: mx.example.com;\r\n"
        b"\tspf=pass smtp.mailfrom=bounce@acme-invoices.net;\r\n"
        b"\tdkim=pass header.i=@acme-invoices.net\r\n"
        b"DKIM-Signature: v=1; a=rsa-sha256; d=acme-invoices.net; s=s1;\r\n"
        b"\tbh=QUJD; h=From:Subject; b=U0lH\r\n"
        b"\r\nbody\r\n"
    )
    analysis = _analyze(data)
    codes = _obs_codes(analysis)
    assert "spf-alignment-aligned" in codes
    assert "dkim-alignment-aligned" in codes
    obs = next(o for o in analysis.observations if o.code == "spf-alignment-aligned")
    assert obs.basis["strict"] is True


def test_alignment_relaxed_subdomain():
    data = (
        b"From: Billing <billing@acme-invoices.net>\r\n"
        b"To: b@example.com\r\n"
        b"Subject: x\r\n"
        b"Date: Fri, 02 Oct 2026 12:00:00 +0000\r\n"
        b"Message-ID: <al-2@acme-invoices.net>\r\n"
        b"Authentication-Results: mx.example.com;\r\n"
        b"\tspf=pass smtp.mailfrom=bounce@mail.acme-invoices.net\r\n"
        b"\r\nbody\r\n"
    )
    analysis = _analyze(data)
    assert "spf-alignment-relaxed-aligned" in _obs_codes(analysis)


def test_alignment_misaligned():
    analysis = _analyze(auth_misaligned_eml())
    assert "spf-alignment-unaligned" in _obs_codes(analysis)
    obs = next(o for o in analysis.observations if o.code == "spf-alignment-unaligned")
    assert obs.basis["spf_domain"] == "evil-relay.example"
    assert obs.basis["strict"] is False
    assert obs.basis["relaxed"] is False


def test_alignment_unknown_without_from_domain():
    data = (
        b"To: b@example.com\r\n"
        b"Subject: x\r\n"
        b"Date: Fri, 02 Oct 2026 12:00:00 +0000\r\n"
        b"Message-ID: <al-3@example.com>\r\n"
        b"Authentication-Results: mx.example.com;\r\n"
        b"\tspf=pass smtp.mailfrom=a@example.net\r\n"
        b"\r\nbody\r\n"
    )
    analysis = _analyze(data)
    assert "spf-alignment-unknown" in _obs_codes(analysis)


# ---------------------------------------------------------------------------
# Whole-analysis behavior
# ---------------------------------------------------------------------------


def test_no_auth_headers_observed_not_failed():
    analysis = _analyze(simple_text())
    assert "no-auth-headers" in _obs_codes(analysis)
    assert analysis.auth_results == []
    assert analysis.dkim_signatures == []
    assert analysis.received_spf == []


def test_provenance():
    analysis = _analyze(auth_all_pass_eml())
    p = analysis.provenance.to_dict()
    assert p["parser_name"] == PARSER_NAME == "phishscope.auth"
    assert p["parser_version"] == PARSER_VERSION == "0.3.0"
    assert p["phishscope_version"] == "0.4.0"
    assert p["analyzed_at_utc"]


def test_deterministic_json():
    a = _analyze(auth_all_pass_eml())
    b = _analyze(auth_all_pass_eml())
    da, db = a.to_dict(), b.to_dict()
    da["provenance"].pop("analyzed_at_utc")
    db["provenance"].pop("analyzed_at_utc")
    assert json.dumps(da, sort_keys=True) == json.dumps(db, sort_keys=True)


def test_no_network_access(tmp_path, monkeypatch):
    """Auth analysis must never open a socket (no DNS, ever)."""

    def _blocked(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
    path = write_eml(tmp_path, auth_all_pass_eml())
    assert main(["auth", path, "--json"]) == 0
    assert main(["analyze", "--headers", path]) == 0


def test_plugin_registered():
    from phishscope.core.plugins import get_registry

    info = get_registry().get("auth")
    assert info.version == "0.3.0"
    assert "auth" in info.commands


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_auth_human(tmp_path, capsys):
    path = write_eml(tmp_path, auth_all_pass_eml())
    assert main(["auth", path]) == 0
    out = capsys.readouterr().out
    assert "authentication (header claims only)" in out
    assert "spf=pass" in out
    assert "OFFLINE BOUNDARY" in out
    assert "NOT cryptographically verified" in out


def test_auth_json(tmp_path, capsys):
    path = write_eml(tmp_path, auth_all_pass_eml())
    assert main(["auth", path, "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["status"] == "ok"
    assert data["command"] == "auth"
    auth = data["message"]["authentication"]
    assert auth["provenance"]["parser_name"] == "phishscope.auth"
    assert len(auth["auth_results"]) == 3
    assert len(auth["dkim_signatures"]) == 1


def test_auth_malformed_exit_1(tmp_path, capsys):
    path = write_eml(tmp_path, auth_malformed_eml())
    assert main(["auth", path]) == 1


def test_auth_missing_file_exit_2(capsys):
    assert main(["auth", "/nonexistent/x.eml"]) == 2


def test_analyze_headers_includes_authentication(tmp_path, capsys):
    path = write_eml(tmp_path, auth_all_pass_eml())
    assert main(["analyze", "--headers", path, "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert "authentication" in data["message"]
    assert data["message"]["authentication"]["from_domain"] == "example.net"


def test_analyze_headers_human_renders_auth_section(tmp_path, capsys):
    path = write_eml(tmp_path, auth_dkim_none_eml())
    assert main(["analyze", "--headers", path]) == 0
    out = capsys.readouterr().out
    assert "Authentication (header claims only" in out
    assert "dkim-signature-absent" in out


def test_analyze_without_headers_flag_has_no_auth(tmp_path, capsys):
    path = write_eml(tmp_path, auth_all_pass_eml())
    assert main(["analyze", path, "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert "authentication" not in data["message"]


def test_help_lists_auth(capsys):
    assert main(["--help"]) == 0
    out = capsys.readouterr().out
    assert "SPF/DKIM/DMARC" in out
    assert main(["auth", "--help"]) == 0
