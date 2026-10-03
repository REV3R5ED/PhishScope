"""Tests for PhishScope v0.4: URL/domain extraction and triage."""

from __future__ import annotations

import json
import socket

from conftest import (
    urls_defanged_eml,
    urls_malformed_eml,
    urls_none_eml,
    urls_variety_eml,
    write_eml,
)

from phishscope.cli.main import main
from phishscope.core import config as config_mod
from phishscope.urls.analysis import analyze_urls
from phishscope.urls.decompose import decompose, dedup_key
from phishscope.urls.defang import (
    defang_url,
    iter_url_candidates,
    looks_defanged,
    undefang_url,
)


def _analyze(data: bytes):
    return analyze_urls(data, "test.eml", config_mod.default_config())


def _urls_by_host(analysis):
    return {u.host: u for u in analysis.urls}


# ---------------------------------------------------------------------------
# defang / undefang
# ---------------------------------------------------------------------------


def test_defang_undefang_round_trip():
    for url in (
        "http://example.com/path?q=1",
        "https://sub.example.co.uk:8443/a/b?x=1&y=2#frag",
        "http://192.0.2.1:8080/x",
        "https://xn--pple-43d.example/verify",
    ):
        defanged = defang_url(url)
        assert "http" not in defanged.split("://")[0]
        assert "[.]" in defanged
        assert undefang_url(defanged) == url


def test_undefang_variants():
    assert undefang_url("hxxps://evil[.]example/a") == "https://evil.example/a"
    assert undefang_url("hxxp://evil[.]example/a") == "http://evil.example/a"
    assert undefang_url("http[:]//evil[.]example/a") == "http://evil.example/a"
    assert undefang_url("https://plain.example/a") == "https://plain.example/a"


def test_looks_defanged():
    assert looks_defanged("hxxp://evil[.]example")
    assert looks_defanged("http[:]//evil.example")
    assert not looks_defanged("https://evil.example/path")


def test_defanged_in_source_observed(tmp_path):
    analysis = _analyze(urls_defanged_eml())
    by_host = _urls_by_host(analysis)
    record = by_host["evil.example"]
    assert record.url == "https://evil.example/login"
    assert "defanged-in-source" in record.observation_codes
    assert any(s.defanged_in_source for s in record.sources)


# ---------------------------------------------------------------------------
# extraction: text, HTML, headers
# ---------------------------------------------------------------------------


def test_extract_from_text_body():
    analysis = _analyze(urls_variety_eml())
    by_host = _urls_by_host(analysis)
    assert "billing.acme-invoices.net" in by_host
    record = by_host["billing.acme-invoices.net"]
    assert any(s.kind == "body-text" for s in record.sources)


def test_extract_from_html_href_and_text():
    analysis = _analyze(urls_variety_eml())
    by_host = _urls_by_host(analysis)
    # href target recorded structurally ...
    steal = by_host["secure-login.example.net"]
    assert any(s.kind == "html-href" for s in steal.sources)
    # ... and the visible display URL recorded as its own sighting
    shown = by_host["www.acme-invoices.net"]
    assert any(s.kind == "html-text" for s in shown.sources)


def test_extract_from_headers():
    analysis = _analyze(urls_variety_eml())
    by_host = _urls_by_host(analysis)
    record = by_host["lists.acme-invoices.net"]
    assert any(
        s.kind == "header" and s.detail == "List-Unsubscribe" for s in record.sources
    )
    assert record.query_params == [["user", "9917"]]


def test_attachment_filename_not_a_url():
    analysis = _analyze(urls_variety_eml())
    hosts = {u.host for u in analysis.urls}
    assert "http-invoice.pdf" not in hosts
    assert not any("http-invoice" in u.url for u in analysis.urls)


def test_dedup_merges_sources():
    analysis = _analyze(urls_variety_eml())
    by_host = _urls_by_host(analysis)
    # https://billing.acme-invoices.net/inv/4821 appears twice in the
    # text body — one deduplicated record; the repeated hit at the
    # same location bumps a count instead of duplicating the source.
    record = by_host["billing.acme-invoices.net"]
    assert len(analysis.urls) == len({u.url for u in analysis.urls})
    body_sightings = [s for s in record.sources if s.kind == "body-text"]
    assert len(body_sightings) == 1
    assert body_sightings[0].count == 2


def test_no_urls_message():
    analysis = _analyze(urls_none_eml())
    assert analysis.urls == []
    assert any(o.code == "no-urls" for o in analysis.observations)


# ---------------------------------------------------------------------------
# decomposition
# ---------------------------------------------------------------------------


def test_decompose_components():
    d = decompose("https://user:pw@sub.example.com:8443/a/b?x=1&y=2#frag")
    assert d.scheme == "https"
    assert d.host == "sub.example.com"
    assert d.port == 8443
    assert d.path == "/a/b"
    assert d.query_params == [["x", "1"], ["y", "2"]]
    assert d.fragment == "frag"
    assert d.userinfo == "user:pw"
    assert d.registered_domain == "example.com"
    assert d.subdomain_depth == 1
    assert d.tld == "com"
    assert d.nonstandard_port is True
    assert d.host_is_ip is False


def test_decompose_defaults():
    d = decompose("http://example.com/")
    assert d.port is None
    assert d.nonstandard_port is False
    d2 = decompose("https://example.com:443/")
    # default port folds away in the dedup key
    assert dedup_key(d2) == "https://example.com/"


def test_ip_literal_detection():
    d = decompose("http://192.0.2.44:8080/x")
    assert d.host_is_ip is True
    assert d.ip_version == 4
    assert d.registered_domain is None
    assert d.nonstandard_port is True


def test_ipv6_literal_detection():
    d = decompose("http://[2001:db8::1]/x")
    assert d.host_is_ip is True
    assert d.ip_version == 6


def test_punycode_decoded_for_display():
    analysis = _analyze(urls_variety_eml())
    by_host = _urls_by_host(analysis)
    record = by_host["xn--pple-43d.example"]
    assert record.punycode is True
    assert record.host_unicode != record.host
    assert "punycode-host" in record.observation_codes


def test_query_values_kept_as_evidence():
    analysis = _analyze(urls_variety_eml())
    by_host = _urls_by_host(analysis)
    record = by_host["track.example.org"]
    names = [n for n, _v in record.query_params]
    assert names == ["utm_source", "utm_medium", "utm_campaign", "sid", "ts", "sig"]
    values = dict(record.query_params)
    assert values["sid"] == "9917"  # values are evidence, not redacted
    assert "many-query-params" in record.observation_codes


# ---------------------------------------------------------------------------
# observations
# ---------------------------------------------------------------------------


def test_observation_codes_variety():
    analysis = _analyze(urls_variety_eml())
    by_host = _urls_by_host(analysis)
    assert "ip-literal-host" in by_host["192.0.2.44"].observation_codes
    assert "http-scheme" in by_host["192.0.2.44"].observation_codes
    assert "shortened-url" in by_host["bit.ly"].observation_codes
    assert "nonstandard-port" in by_host["192.0.2.44"].observation_codes
    assert "deep-subdomain" in by_host["a.b.c.d.example.com"].observation_codes
    assert any(o.code == "url-count" for o in analysis.observations)


def test_display_href_mismatch_observation():
    analysis = _analyze(urls_variety_eml())
    mismatches = [o for o in analysis.observations if o.code == "display-href-mismatch"]
    assert len(mismatches) == 1
    basis = mismatches[0].basis
    assert basis["href"] == "https://secure-login.example.net/verify?id=9917"
    assert "www.acme-invoices.net/verify" in basis["display_text"]
    # The observation is a fact, not a verdict — the detail says so.
    assert "phishing" not in mismatches[0].detail.lower()


def test_observations_carry_basis_with_url():
    analysis = _analyze(urls_variety_eml())
    for obs in analysis.observations:
        if obs.code in ("url-count", "no-urls"):
            continue
        assert "url" in obs.basis, f"observation {obs.code} lacks url basis"


def test_shortener_target_not_expanded():
    analysis = _analyze(urls_variety_eml())
    obs = [o for o in analysis.observations if o.code == "shortened-url"][0]
    assert "not expanded" in obs.detail.lower()
    assert "offline" in obs.detail.lower()


# ---------------------------------------------------------------------------
# malformed input
# ---------------------------------------------------------------------------


def test_malformed_urls_do_not_crash():
    analysis = _analyze(urls_malformed_eml())
    # bare "http://" never matches; bad bracket/port become warnings
    assert analysis.urls == [] or all(u.host for u in analysis.urls)
    codes = {w.code for w in analysis.parser_warnings}
    assert "url-unparseable" in codes


def test_huge_url_handled():
    analysis = _analyze(urls_malformed_eml())
    # the 3000-char URL must not crash extraction; it may parse or warn
    assert isinstance(analysis.urls, list)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_urls_human_defanged(tmp_path, capsys):
    path = write_eml(tmp_path, urls_variety_eml())
    assert main(["urls", path]) == 0
    out = capsys.readouterr().out
    assert "hxxps://secure-login[.]example[.]net/verify?id=9917" in out
    assert "https://secure-login.example.net" not in out  # never clickable
    assert "OFFLINE BOUNDARY" in out


def test_cli_urls_json_exact(tmp_path, capsys):
    path = write_eml(tmp_path, urls_variety_eml())
    assert main(["urls", path, "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["status"] == "ok"
    urls = data["message"]["urls"]
    assert urls["url_count"] > 0
    first = urls["urls"][0]
    # exact values in --json, never defanged
    assert first["url"].startswith(("http://", "https://"))
    assert "[.]" not in first["url"]
    assert first["defanged"] != first["url"]
    assert urls["provenance"]["parser_name"] == "phishscope.urls"


def test_cli_analyze_urls_flag(tmp_path, capsys):
    path = write_eml(tmp_path, urls_variety_eml())
    assert main(["analyze", path, "--urls"]) == 0
    out = capsys.readouterr().out
    assert "URLs (" in out
    assert "hxxp" in out or "hxxps" in out


def test_cli_analyze_urls_json_block(tmp_path, capsys):
    path = write_eml(tmp_path, urls_variety_eml())
    assert main(["analyze", path, "--urls", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert "urls" in data["message"]
    assert data["message"]["urls"]["provenance"]["parser_version"] == "0.4.0"


def test_cli_urls_missing_file(capsys):
    assert main(["urls", "/nonexistent/message.eml"]) == 2


def test_no_network_access(tmp_path, monkeypatch):
    """URL analysis must never open a socket, even implicitly."""

    def _blocked(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
    path = write_eml(tmp_path, urls_variety_eml())
    assert main(["urls", path, "--json"]) == 0
    assert main(["analyze", path, "--urls"]) == 0


def test_plugin_registered():
    from phishscope.core.plugins import get_registry

    info = get_registry().get("urls")
    assert info.version == "0.4.0"
    assert info.commands == ["urls"]


def test_iter_url_candidates_edge_cases():
    # trailing punctuation stripped
    found = iter_url_candidates("see https://example.com/path, now.")
    assert found[0][0] == "https://example.com/path"
    # balanced parens preserved
    found = iter_url_candidates("(https://example.com/a_(b))")
    assert found[0][0] == "https://example.com/a_(b)"
    # bare scheme word never matches
    assert iter_url_candidates("the https protocol") == []
