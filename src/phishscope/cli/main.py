"""PhishScope CLI: analyze / overview / hops / auth / urls / attachments.

Every command renders human-readable text by default (``--json`` for
automation), uses structured exit codes (0 ok / 1 parser warnings /
2 error), and writes an audit record. Diagnostics go to stderr;
stdout carries only the requested output.

Forensic posture: the source file is only ever opened read-only, the
SHA-256 is computed before any parsing, and URLs in human output are
defanged so they cannot be followed by accident. ``--show-raw`` prints
the original bytes behind an explicit safety banner. Header forensics
never resolves hostnames and never fetches anything — observations
describe what the headers claim, not what is true. Authentication
analysis is fully offline: no DNS lookups, no DKIM key retrieval, no
signature verification; results record header claims only. URL
analysis is fully offline too: URLs are extracted and decomposed
locally, never fetched, never resolved.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence
from typing import Any

from phishscope import __version__
from phishscope.attachments.analysis import analyze_attachments
from phishscope.attachments.models import AttachmentAnalysis
from phishscope.auth.analysis import analyze_auth
from phishscope.auth.models import AuthAnalysis
from phishscope.core import config as config_mod
from phishscope.core.config import AppConfig
from phishscope.core.logging import audit_log, configure_logging, get_logger
from phishscope.core.models import NormalizedMessage
from phishscope.core.results import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, Result
from phishscope.headers.analysis import analyze_headers
from phishscope.headers.models import HeaderAnalysis
from phishscope.parsers import safe_eml
from phishscope.parsers.safe_eml import ParseError
from phishscope.urls.analysis import analyze_urls
from phishscope.urls.models import UrlAnalysis

log = get_logger()

RAW_SAFETY_BANNER = """\
================================================================================
SAFETY NOTICE — RAW MESSAGE BYTES BELOW
--------------------------------------------------------------------------------
This is the original, unmodified message exactly as received. PhishScope did
not render, execute, download, or otherwise act on anything in it to produce
this output. Treat every URL and attachment below as hostile: do not click
links, do not open attachments, do not copy content into other tools without
thinking.
================================================================================"""

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def defang_text(value: str) -> str:
    """Defang URLs in a display string so they cannot be followed.

    ``http://``/``https://`` become ``hxxp://``/``hxxps://`` and dots
    become ``[.]``. Only used for human-readable output — ``--json``
    always carries exact values for tooling.
    """

    def _replace(match: re.Match[str]) -> str:
        url = match.group(0)
        url = url.replace("https://", "hxxps://").replace("http://", "hxxp://")
        return url.replace(".", "[.]")

    return _URL_RE.sub(_replace, value)


def truncate(value: str, limit: int) -> str:
    """Truncate a display string, noting the truncation."""
    if len(value) <= limit:
        return value
    return value[:limit] + f"… [{len(value) - limit} more chars, see --json]"


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _addr_display(addr: dict[str, Any] | None) -> str:
    if not addr:
        return "—"
    name = addr.get("display_name") or ""
    email_addr = addr.get("addr") or ""
    if name and email_addr:
        return f"{name} <{email_addr}>"
    return email_addr or name or "—"


def _disp(value: str | None, cfg: AppConfig, defang: bool = True) -> str:
    """Display rendering: truncate + optionally defang."""
    text = truncate(value or "—", cfg.display_truncate_len)
    return defang_text(text) if defang else text


def _addrs(addrs: list[dict[str, Any]], cfg: AppConfig) -> str:
    """Comma-joined address displays, truncated + defanged."""
    joined = ", ".join(_addr_display(a) for a in addrs)
    return _disp(joined or "—", cfg)


def render_analyze_human(msg: NormalizedMessage, cfg: AppConfig) -> str:
    """Full human-readable analysis report."""
    date = msg.date
    if date.valid and date.utc:
        date_line = f"{date.utc}  (original: {_disp(date.original, cfg, defang=False)})"
    elif date.original:
        date_line = (
            f"<unparseable>  (original: {_disp(date.original, cfg, defang=False)})"
        )
    else:
        date_line = "<missing>"
    from_addr = msg.from_addr.to_dict() if msg.from_addr else None
    lines = [
        f"PhishScope v{__version__} — message analysis",
        "",
        f"Evidence ID : {msg.evidence_id}",
        f"Source      : {msg.source_path}",
        f"SHA-256     : {msg.sha256}",
        f"Size        : {msg.size_bytes:,} bytes",
        f"Date        : {date_line}",
        f"From        : {_disp(_addr_display(from_addr), cfg)}",
        f"To          : {_addrs([a.to_dict() for a in msg.to], cfg)}",
    ]
    if msg.cc:
        lines.append(f"Cc          : {_addrs([a.to_dict() for a in msg.cc], cfg)}")
    if msg.reply_to:
        lines.append(
            f"Reply-To    : {_addrs([a.to_dict() for a in msg.reply_to], cfg)}"
        )
    if msg.return_path:
        lines.append(
            f"Return-Path : {_disp(_addr_display(msg.return_path.to_dict()), cfg)}"
        )
    lines.append(f"Subject     : {_disp(msg.subject, cfg)}")
    lines.append(f"Message-ID  : {_disp(msg.message_id, cfg, defang=False)}")
    lines.append("")
    lines.append(_render_mime_tree(msg))
    lines.append("")
    lines.append(_render_attachments(msg))
    lines.append("")
    lines.append(_render_warnings(msg))
    return "\n".join(lines)


def _render_mime_tree(msg: NormalizedMessage) -> str:
    lines = ["MIME structure:"]
    _render_part(msg.mime_tree.to_dict(), lines, indent="  ")
    return "\n".join(lines)


def _render_part(part: dict[str, Any], lines: list[str], indent: str) -> None:
    label = f"[{part['index']}] {part['content_type']}"
    if part["filename"]:
        label += f" — {part['filename']}"
    label += f" ({part['size_bytes']:,} bytes)"
    if part["is_attachment"]:
        label += " [attachment]"
    lines.append(indent + label)
    for child in part["children"]:
        _render_part(child, lines, indent + "  ")


def _render_attachments(msg: NormalizedMessage) -> str:
    if not msg.attachments:
        return "Attachments: none"
    lines = [f"Attachments ({len(msg.attachments)}):"]
    for att in msg.attachments:
        d = att.to_dict()
        lines.append(
            f"  {d['filename']} — {d['mime_claim']}, "
            f"{d['size_bytes']:,} bytes, sha256:{d['sha256'][:16]}…"
        )
    lines.append("  (content not extracted in v0.1 — hashes only)")
    return "\n".join(lines)


def _render_warnings(msg: NormalizedMessage) -> str:
    if not msg.parser_warnings:
        return "Parser warnings: none"
    lines = [f"Parser warnings ({len(msg.parser_warnings)}):"]
    for warn in msg.parser_warnings:
        d = warn.to_dict()
        where = f" [part {d['part']}]" if d["part"] else ""
        lines.append(f"  [!] {d['code']}{where}: {d['detail']}")
    return "\n".join(lines)


def _hop_endpoint(host: str | None, ip: str | None) -> str:
    """Human display of a from/by endpoint: host, ip, or both."""
    if host and ip:
        return f"{host} [{ip}]"
    if ip:
        return f"[{ip}]"
    return host or "—"


def _hop_timestamp(hop: dict[str, Any]) -> str:
    if hop["timestamp_valid"] and hop["timestamp_utc"]:
        return str(hop["timestamp_utc"])
    if hop["timestamp_original"]:
        return f"<unparseable: {hop['timestamp_original']}>"
    return "<missing>"


def render_hops_human(analysis: HeaderAnalysis, cfg: AppConfig) -> str:
    """Focused Received-chain view, oldest hop first."""
    d = analysis.to_dict()
    lines = [
        f"PhishScope v{__version__} — Received chain (oldest → newest)",
        "",
        f"Evidence ID : {d['evidence_id']}",
        f"Source      : {d['source_path']}",
        f"Hops        : {len(d['received'])}",
        "",
    ]
    if not d["received"]:
        lines.append("No Received headers present; routing path is unobserved.")
    for hop in d["received"]:
        lines.append(f"[hop {hop['position']}] {_hop_timestamp(hop)}")
        from_ep = _disp(
            _hop_endpoint(hop["from_host"], hop["from_ip"]), cfg, defang=False
        )
        by_ep = _disp(_hop_endpoint(hop["by_host"], hop["by_ip"]), cfg, defang=False)
        lines.append(f"  from : {from_ep}")
        lines.append(f"  by   : {by_ep}")
        extra = []
        if hop["with_protocol"]:
            extra.append(f"with {hop['with_protocol']}")
        if hop["hop_id"]:
            extra.append(f"id {hop['hop_id']}")
        if extra:
            lines.append(f"         {', '.join(extra)}")
    lines.append("")
    lines.append(_render_observations(d, cfg))
    header_warnings = d["parser_warnings"]
    if header_warnings:
        lines.append("")
        lines.append(f"Header parser warnings ({len(header_warnings)}):")
        for warn in header_warnings:
            lines.append(
                f"  [!] {warn['code']}: "
                f"{truncate(warn['detail'], cfg.display_truncate_len)}"
            )
    return "\n".join(lines)


def _render_observations(d: dict[str, Any], cfg: AppConfig) -> str:
    observations = d["observations"]
    if not observations:
        return "Observations: none"
    lines = [f"Observations ({len(observations)}) — facts, not verdicts:"]
    for obs in observations:
        lines.append(
            f"  [•] {obs['code']}: {truncate(obs['detail'], cfg.display_truncate_len)}"
        )
    return "\n".join(lines)


def render_headers_section(analysis: HeaderAnalysis, cfg: AppConfig) -> str:
    """Routing-headers section appended to ``analyze --headers`` output."""
    d = analysis.to_dict()
    lines = ["Routing headers:"]
    lines.append(f"  Return-Path : {_disp(_addr_display(d['return_path']), cfg)}")
    lines.append(f"  Message-ID  : {_disp(d['message_id'], cfg, defang=False)}")
    if d["x_originating_ip"]:
        lines.append(f"  X-Originating-IP : {d['x_originating_ip']}")
    if d["x_sender_ip"]:
        lines.append(f"  X-Sender-IP      : {d['x_sender_ip']}")
    if d["x_mailer"]:
        lines.append(f"  X-Mailer      : {_disp(d['x_mailer'], cfg, defang=False)}")
    if d["user_agent"]:
        lines.append(f"  User-Agent    : {_disp(d['user_agent'], cfg, defang=False)}")
    for name, value in d["list_headers"].items():
        lines.append(f"  {name:<14}: {_disp(value, cfg, defang=False)}")
    lines.append("")
    lines.append(f"  Received chain ({len(d['received'])} hops, oldest → newest):")
    if not d["received"]:
        lines.append("    (none)")
    for hop in d["received"]:
        lines.append(
            f"    [{hop['position']}] {_hop_timestamp(hop)}  "
            f"{_hop_endpoint(hop['from_host'], hop['from_ip'])} → "
            f"{_hop_endpoint(hop['by_host'], hop['by_ip'])}"
        )
    lines.append("")
    lines.append("  " + _render_observations(d, cfg).replace("\n", "\n  "))
    return "\n".join(lines)


def _auth_result_domain(props: dict[str, Any]) -> str | None:
    """Best-effort domain for a rendered auth result (display only)."""
    for key in (
        "header.i",
        "header.d",
        "header.from",
        "smtp.mailfrom",
        "envelope-from",
    ):
        value = props.get(key)
        if not value:
            continue
        domain = str(value).strip().lower().lstrip("@")
        if "@" in domain:
            domain = domain.rsplit("@", 1)[1]
        domain = domain.strip().rstrip(".")
        if domain and domain != "none":
            return domain
    return None


def render_auth_human(analysis: AuthAnalysis, cfg: AppConfig) -> str:
    """Focused authentication view: claims, alignment, never verdicts."""
    d = analysis.to_dict()
    lines = [
        f"PhishScope v{__version__} — authentication (header claims only)",
        "",
        f"Evidence ID : {d['evidence_id']}",
        f"Source      : {d['source_path']}",
        f"From domain : {d['from_domain'] or '<unknown>'}",
        "",
        "OFFLINE BOUNDARY: no DNS lookups, no DKIM key retrieval, no",
        "signature verification. Results below are what the headers claim.",
        "",
    ]
    if d["auth_results"]:
        lines.append("Authentication-Results:")
        for r in d["auth_results"]:
            domain = _auth_result_domain(r["properties"])
            line = f"  {r['method']}={r['result']}  (by {r['authserv_id']})"
            if domain:
                line += f"  domain={_disp(domain, cfg, defang=False)}"
            if r["reason"]:
                line += f"  — {_disp(r['reason'], cfg, defang=False)}"
            lines.append(line)
        lines.append("")
    if d["dkim_signatures"]:
        lines.append("DKIM-Signature claims (NOT cryptographically verified):")
        for s in d["dkim_signatures"]:
            lines.append(
                f"  d={s['d'] or '<missing>'} s={s['s'] or '<missing>'} "
                f"a={s['a'] or '<missing>'} c={s['c'] or '<missing>'} "
                f"bh={truncate(s['bh'] or '<missing>', 24)}"
            )
        lines.append("")
    if d["received_spf"]:
        lines.append("Received-SPF:")
        for s in d["received_spf"]:
            line = f"  {s['result']}"
            if s["detail"]:
                line += f" — {_disp(s['detail'], cfg, defang=False)}"
            lines.append(line)
        lines.append("")
    lines.append(
        _render_observations({"observations": d["observations"]}, cfg).replace(
            "Observations", "Auth observations"
        )
    )
    auth_warnings = d["parser_warnings"]
    if auth_warnings:
        lines.append("")
        lines.append(f"Auth parser warnings ({len(auth_warnings)}):")
        for warn in auth_warnings:
            lines.append(
                f"  [!] {warn['code']}: "
                f"{truncate(warn['detail'], cfg.display_truncate_len)}"
            )
    return "\n".join(lines)


def render_auth_section(analysis: AuthAnalysis, cfg: AppConfig) -> str:
    """Authentication section appended to ``analyze --headers`` output."""
    d = analysis.to_dict()
    lines = ["Authentication (header claims only — offline, never verified):"]
    for r in d["auth_results"]:
        lines.append(f"  {r['method']}={r['result']}  (by {r['authserv_id']})")
    if not d["auth_results"] and not d["dkim_signatures"] and not d["received_spf"]:
        lines.append("  (no authentication headers present)")
    lines.append("")
    lines.append("  " + _render_observations(d, cfg).replace("\n", "\n  "))
    return "\n".join(lines)


def _url_source_display(source: dict[str, Any]) -> str:
    kind = source["kind"]
    detail = source["detail"]
    label = {
        "body-text": f"body text (part {detail})",
        "html-href": f"HTML link target ({detail})",
        "html-src": f"HTML resource ({detail})",
        "html-text": f"HTML visible text (part {detail})",
        "header": f"header {detail}",
    }.get(kind, f"{kind} ({detail})")
    if source["defanged_in_source"]:
        label += " [defanged in source]"
    if source.get("count", 1) > 1:
        label += f" ×{source['count']}"
    return label


def _render_url_observations(d: dict[str, Any], cfg: AppConfig) -> str:
    """URL observations for human output — details are defanged.

    Observation details quote exact URLs (e.g. display-href-mismatch
    names the href); human output must never print a clickable URL,
    so details go through the same defanging as any other display
    text. ``--json`` keeps the exact values.
    """
    observations = d["observations"]
    if not observations:
        return "URL observations: none"
    lines = ["URL observations — facts, not verdicts:"]
    for obs in observations:
        detail = defang_text(truncate(obs["detail"], cfg.display_truncate_len))
        lines.append(f"  [•] {obs['code']}: {detail}")
    return "\n".join(lines)


def render_urls_human(analysis: UrlAnalysis, cfg: AppConfig) -> str:
    """Focused URL/domain inventory: defanged display, local decomposition."""
    d = analysis.to_dict()
    lines = [
        f"PhishScope v{__version__} — URL/domain inventory (offline)",
        "",
        f"Evidence ID : {d['evidence_id']}",
        f"Source      : {d['source_path']}",
        f"URLs        : {d['url_count']} unique",
        "",
        "OFFLINE BOUNDARY: URLs are extracted and decomposed locally —",
        "never fetched, never resolved, shorteners never expanded.",
        "",
    ]
    if not d["urls"]:
        lines.append("No http(s) URLs observed in body, HTML, or headers.")
    for u in d["urls"]:
        lines.append(f"[url] {_disp(u['defanged'], cfg, defang=False)}")
        lines.append(f"  scheme : {u['scheme']}")
        host_line = f"  host   : {u['host']}"
        if u["punycode"]:
            host_line += f"  (IDNA: {_disp(u['host_unicode'], cfg, defang=False)})"
        if u["host_is_ip"]:
            host_line += f"  [IPv{u['ip_version']} literal]"
        lines.append(host_line)
        if u["port"] is not None:
            port_note = " (non-standard)" if u["nonstandard_port"] else ""
            lines.append(f"  port   : {u['port']}{port_note}")
        if u["registered_domain"]:
            lines.append(
                f"  domain : {u['registered_domain']}  (naive last-two-labels)"
            )
        if u["path"]:
            lines.append(f"  path   : {_disp(u['path'], cfg, defang=False)}")
        if u["query_params"]:
            names = ", ".join(n for n, _v in u["query_params"])
            lines.append(
                f"  query  : {len(u['query_params'])} param(s): "
                f"{_disp(names, cfg, defang=False)}"
            )
        sources = "; ".join(_url_source_display(s) for s in u["sources"])
        lines.append(f"  seen in: {_disp(sources, cfg, defang=False)}")
        if u["observation_codes"]:
            lines.append(f"  flags  : {', '.join(u['observation_codes'])}")
        lines.append("")
    lines.append(_render_url_observations(d, cfg))
    url_warnings = d["parser_warnings"]
    if url_warnings:
        lines.append("")
        lines.append(f"URL parser warnings ({len(url_warnings)}):")
        for warn in url_warnings:
            lines.append(
                f"  [!] {warn['code']}: "
                f"{truncate(warn['detail'], cfg.display_truncate_len)}"
            )
    return "\n".join(lines)


def render_urls_section(analysis: UrlAnalysis, cfg: AppConfig) -> str:
    """URL section appended to ``analyze --urls`` output."""
    d = analysis.to_dict()
    lines = [f"URLs ({d['url_count']} unique, offline — never fetched):"]
    if not d["urls"]:
        lines.append("  (none observed)")
    for u in d["urls"]:
        line = f"  {_disp(u['defanged'], cfg, defang=False)}"
        extras = []
        if u["host_is_ip"]:
            extras.append("IP literal")
        if u["punycode"]:
            extras.append("punycode")
        if u["shortener"]:
            extras.append("shortener")
        if u["nonstandard_port"]:
            extras.append(f"port {u['port']}")
        if extras:
            line += f"  [{', '.join(extras)}]"
        lines.append(line)
    lines.append("")
    lines.append("  " + _render_url_observations(d, cfg).replace("\n", "\n  "))
    return "\n".join(lines)


def render_overview_human(msg: NormalizedMessage, cfg: AppConfig) -> str:
    """Compact one-screen summary (defanged)."""
    lim = cfg.display_truncate_len
    d = msg.to_dict()
    date = d["date"]["utc"] or d["date"]["original"] or "<missing>"
    parts = _count_parts(d["mime_tree"])
    digest = d["sha256"][:16]
    lines = [
        f"PhishScope v{__version__} — message overview",
        "",
        f"Evidence : {d['evidence_id']}  |  sha256:{digest}…"
        f"  |  {d['size_bytes']:,} bytes",
        f"Date     : {date}",
        f"From     : {_disp(_addr_display(d['from']), cfg)}",
        f"To       : {_addrs(d['to'], cfg)}",
        f"Subject  : {_disp(d['subject'], cfg)}",
        f"Parts    : {parts} ({d['mime_tree']['content_type']})"
        f"  |  Attachments: {len(d['attachments'])}"
        f"  |  Warnings: {len(d['parser_warnings'])}",
    ]
    if d["attachments"]:
        names = ", ".join(a["filename"] for a in d["attachments"])
        lines.append(f"Files    : {truncate(names, lim)}")
    if d["parser_warnings"]:
        first = d["parser_warnings"][0]
        lines.append(f"Warning  : [{first['code']}] {truncate(first['detail'], lim)}")
    return "\n".join(lines)


def _count_parts(part: dict[str, Any]) -> int:
    return 1 + sum(_count_parts(c) for c in part["children"])


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def _analyze(
    path: str, cfg: AppConfig
) -> tuple[Result, NormalizedMessage | None, bytes]:
    """Run the parser; never raises for expected input problems."""
    try:
        message, raw = safe_eml.parse_file(path, cfg)
    except (ParseError, FileNotFoundError, IsADirectoryError, OSError) as exc:
        return Result(status="error", command="analyze", errors=[str(exc)]), None, b""
    result = Result(status="ok", command="analyze", message=message.to_dict())
    return result, message, raw


def _exit_for(result: Result, extra_warnings: int = 0) -> int:
    """Exit code from a result: 2 error, 1 any warnings, else 0."""
    if result.status == "error":
        return EXIT_ERROR
    base_warnings = 0
    if result.message:
        base_warnings = len(result.message.get("parser_warnings", []))
    if base_warnings + extra_warnings:
        return EXIT_FINDINGS
    return EXIT_OK


def cmd_analyze(args: argparse.Namespace, cfg: AppConfig) -> int:
    result, message, raw = _analyze(args.file, cfg)
    headers: HeaderAnalysis | None = None
    auth: AuthAnalysis | None = None
    urls: UrlAnalysis | None = None
    attachments: AttachmentAnalysis | None = None
    if args.headers and result.status != "error":
        # Raw bytes are already in hand; header + auth analysis
        # re-derive from them (never from the normalized model) and
        # never touch the network.
        headers = analyze_headers(raw, args.file, cfg)
        auth = analyze_auth(raw, args.file, cfg)
        if result.message is not None:
            result.message["headers"] = headers.to_dict()
            result.message["authentication"] = auth.to_dict()
    if args.urls and result.status != "error":
        # Offline URL inventory: extracted and decomposed locally —
        # never fetched, never resolved.
        urls = analyze_urls(raw, args.file, cfg)
        if result.message is not None:
            result.message["urls"] = urls.to_dict()
    if args.attachments and result.status != "error":
        # In-memory attachment forensics: never written to disk,
        # never executed, never rendered.
        attachments = analyze_attachments(raw, args.file, cfg)
        if result.message is not None:
            result.message["attachments_detail"] = attachments.to_dict()
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    elif result.status == "error":
        print(f"phishscope: error: {'; '.join(result.errors)}", file=sys.stderr)
    elif message is not None:
        if args.show_raw:
            print(RAW_SAFETY_BANNER)
            print()
            print(raw.decode("utf-8", errors="replace"))
        else:
            print(render_analyze_human(message, cfg))
            if headers is not None:
                print()
                print(render_headers_section(headers, cfg))
            if auth is not None:
                print()
                print(render_auth_section(auth, cfg))
            if urls is not None:
                print()
                print(render_urls_section(urls, cfg))
            if attachments is not None:
                print()
                print(render_attachments_section(attachments, cfg))
    extra = (
        (len(headers.parser_warnings) if headers else 0)
        + (len(auth.parser_warnings) if auth else 0)
        + (len(urls.parser_warnings) if urls else 0)
        + (len(attachments.parser_warnings) if attachments else 0)
    )
    code = _exit_for(result, extra)
    audit_log({"command": ["analyze", args.file], "exit": code})
    return code


def cmd_overview(args: argparse.Namespace, cfg: AppConfig) -> int:
    result, message, _raw = _analyze(args.file, cfg)
    result.command = "overview"
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    elif result.status == "error":
        print(f"phishscope: error: {'; '.join(result.errors)}", file=sys.stderr)
    elif message is not None:
        print(render_overview_human(message, cfg))
    code = _exit_for(result)
    audit_log({"command": ["overview", args.file], "exit": code})
    return code


def cmd_hops(args: argparse.Namespace, cfg: AppConfig) -> int:
    result, _message, raw = _analyze(args.file, cfg)
    result.command = "hops"
    analysis: HeaderAnalysis | None = None
    if result.status != "error":
        analysis = analyze_headers(raw, args.file, cfg)
        result.message = {"headers": analysis.to_dict()}
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    elif result.status == "error":
        print(f"phishscope: error: {'; '.join(result.errors)}", file=sys.stderr)
    elif analysis is not None:
        print(render_hops_human(analysis, cfg))
    code = _exit_for(result, len(analysis.parser_warnings) if analysis else 0)
    audit_log({"command": ["hops", args.file], "exit": code})
    return code


def cmd_auth(args: argparse.Namespace, cfg: AppConfig) -> int:
    result, _message, raw = _analyze(args.file, cfg)
    result.command = "auth"
    analysis: AuthAnalysis | None = None
    if result.status != "error":
        # Offline: parses header claims only — no DNS, no key retrieval,
        # no signature verification.
        analysis = analyze_auth(raw, args.file, cfg)
        result.message = {"authentication": analysis.to_dict()}
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    elif result.status == "error":
        print(f"phishscope: error: {'; '.join(result.errors)}", file=sys.stderr)
    elif analysis is not None:
        print(render_auth_human(analysis, cfg))
    code = _exit_for(result, len(analysis.parser_warnings) if analysis else 0)
    audit_log({"command": ["auth", args.file], "exit": code})
    return code


def cmd_urls(args: argparse.Namespace, cfg: AppConfig) -> int:
    result, _message, raw = _analyze(args.file, cfg)
    result.command = "urls"
    analysis: UrlAnalysis | None = None
    if result.status != "error":
        # Offline: URLs are extracted and decomposed locally — never
        # fetched, never resolved, shorteners never expanded.
        analysis = analyze_urls(raw, args.file, cfg)
        result.message = {"urls": analysis.to_dict()}
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    elif result.status == "error":
        print(f"phishscope: error: {'; '.join(result.errors)}", file=sys.stderr)
    elif analysis is not None:
        print(render_urls_human(analysis, cfg))
    code = _exit_for(result, len(analysis.parser_warnings) if analysis else 0)
    audit_log({"command": ["urls", args.file], "exit": code})
    return code


def _render_attachment_observations(d: dict[str, Any], cfg: AppConfig) -> str:
    observations = d["observations"]
    if not observations:
        return "Attachment observations — facts, not verdicts:\n  (none)"
    lines = ["Attachment observations — facts, not verdicts:"]
    for obs in observations:
        detail = truncate(obs["detail"], cfg.display_truncate_len)
        lines.append(f"  [•] {obs['code']}: {detail}")
    return "\n".join(lines)


def _render_archive(inv: dict[str, Any], indent: str) -> list[str]:
    header = f"{indent}archive: {inv['format']} ({inv['member_count']} member(s)"
    if inv["truncated"]:
        header += ", truncated"
    if inv["encrypted_entries"]:
        header += f", {inv['encrypted_entries']} encrypted"
    header += ")"
    lines = [header]
    for member in inv["members"]:
        enc = " [encrypted]" if member["encrypted"] else ""
        lines.append(f"{indent}  - {member['name']}{enc}")
    for nested in inv["nested_inventories"]:
        lines.append(f"{indent}  [nested]")
        lines.extend(_render_archive(nested, indent + "    "))
    return lines


def render_attachments_human(
    analysis: AttachmentAnalysis, cfg: AppConfig, full_hash: bool = False
) -> str:
    """Focused attachment inventory: in-memory analysis, never on disk."""
    d = analysis.to_dict()
    lines = [
        f"PhishScope v{__version__} — attachment inventory (in-memory only)",
        "",
        f"Evidence ID : {d['evidence_id']}",
        f"Source      : {d['source_path']}",
        f"Attachments : {len(d['attachments'])}",
        "",
        "SAFETY BOUNDARY: attachment bytes are analyzed in memory only —",
        "never written to disk, never executed, never rendered. Archive",
        "members are listed by name only; encrypted entries are never read.",
        "",
    ]
    if not d["attachments"]:
        lines.append("No attachments observed in this message.")
    for a in d["attachments"]:
        ident = a["identified"]
        lines.append(f"[attachment] {_disp(a['filename'], cfg)}")
        lines.append(f"  part   : {a['part_index']}")
        lines.append(f"  claimed: {a['mime_claim']}")
        lines.append(f"  magic  : {ident['label']} ({ident['detail']})")
        lines.append(f"  size   : {a['size_bytes']:,} bytes")
        if full_hash:
            lines.append(f"  sha256 : {a['sha256']}")
            lines.append(f"  md5    : {a['md5']}")
        else:
            lines.append(f"  sha256 : {a['sha256'][:16]}…  (--hash for full)")
        if a["archive"] is not None:
            lines.extend(_render_archive(a["archive"], "  "))
        if a["ole"] is not None and (a["ole"]["storages"] or a["ole"]["streams"]):
            lines.append(
                f"  ole    : {len(a['ole']['storages'])} storage(s), "
                f"{len(a['ole']['streams'])} stream(s)"
            )
        if a["observation_codes"]:
            lines.append(f"  flags  : {', '.join(a['observation_codes'])}")
        lines.append("")
    lines.append(_render_attachment_observations(d, cfg))
    att_warnings = d["parser_warnings"]
    if att_warnings:
        lines.append("")
        lines.append(f"Attachment parser warnings ({len(att_warnings)}):")
        for warn in att_warnings:
            lines.append(
                f"  [!] {warn['code']}: "
                f"{truncate(warn['detail'], cfg.display_truncate_len)}"
            )
    return "\n".join(lines)


def render_attachments_section(analysis: AttachmentAnalysis, cfg: AppConfig) -> str:
    """Attachment section appended to ``analyze --attachments`` output."""
    d = analysis.to_dict()
    lines = [f"Attachments ({len(d['attachments'])}, in-memory only):"]
    if not d["attachments"]:
        lines.append("  (none observed)")
    for a in d["attachments"]:
        line = f"  {_disp(a['filename'], cfg)}"
        extras = [a["identified"]["label"], f"{a['size_bytes']:,} bytes"]
        if a["observation_codes"]:
            extras.append(", ".join(a["observation_codes"]))
        line += f"  [{'; '.join(extras)}]"
        lines.append(line)
    lines.append("")
    lines.append("  " + _render_attachment_observations(d, cfg).replace("\n", "\n  "))
    return "\n".join(lines)


def cmd_attachments(args: argparse.Namespace, cfg: AppConfig) -> int:
    result, _message, raw = _analyze(args.file, cfg)
    result.command = "attachments"
    analysis: AttachmentAnalysis | None = None
    if result.status != "error":
        # In-memory only: bytes are hashed/identified/listed in RAM —
        # never written to disk, never executed, never rendered.
        try:
            analysis = analyze_attachments(raw, args.file, cfg)
        except ValueError as exc:
            result.status = "error"
            result.errors.append(str(exc))
        else:
            result.message = {"attachments": analysis.to_dict()}
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    elif result.status == "error":
        print(f"phishscope: error: {'; '.join(result.errors)}", file=sys.stderr)
    elif analysis is not None:
        print(render_attachments_human(analysis, cfg, full_hash=args.hash))
    code = _exit_for(result, len(analysis.parser_warnings) if analysis else 0)
    audit_log({"command": ["attachments", args.file], "exit": code})
    return code


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--json",
        action="store_true",
        help="machine-readable JSON output (exact values, never defanged)",
    )
    common.add_argument(
        "--verbose", action="store_true", help="debug diagnostics on stderr"
    )

    parser = argparse.ArgumentParser(
        prog="phishscope",
        description="PhishScope — email and phishing forensics. "
        "Trace the message. Expose the evidence.",
        parents=[common],
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_analyze = sub.add_parser(
        "analyze",
        parents=[common],
        help="full safe analysis of a .eml message → normalized message model",
    )
    p_analyze.add_argument("file", help="path to the .eml / RFC 5322 message")
    p_analyze.add_argument(
        "--show-raw",
        action="store_true",
        help="print the original message bytes behind a safety banner "
        "(human output only; raw bytes never appear in --json)",
    )
    p_analyze.add_argument(
        "--headers",
        action="store_true",
        help="include header forensics: normalized routing headers and the "
        "Received chain (oldest-to-newest) with observation-only analysis",
    )
    p_analyze.add_argument(
        "--urls",
        action="store_true",
        help="include URL/domain inventory: locally extracted and "
        "decomposed URLs (never fetched, never resolved) with "
        "observation-only analysis",
    )
    p_analyze.add_argument(
        "--attachments",
        action="store_true",
        help="include attachment forensics: magic-byte identification, "
        "declared-vs-identified type observations, archive inventory "
        "by name only (in memory — never written to disk, never executed)",
    )
    p_analyze.set_defaults(func=cmd_analyze)

    p_overview = sub.add_parser(
        "overview",
        parents=[common],
        help="compact human-readable summary of a .eml message",
    )
    p_overview.add_argument("file", help="path to the .eml / RFC 5322 message")
    p_overview.set_defaults(func=cmd_overview)

    p_hops = sub.add_parser(
        "hops",
        parents=[common],
        help="focused Received-chain view: each hop oldest-to-newest with "
        "observation-only chain forensics (never resolves hostnames)",
    )
    p_hops.add_argument("file", help="path to the .eml / RFC 5322 message")
    p_hops.set_defaults(func=cmd_hops)

    p_auth = sub.add_parser(
        "auth",
        parents=[common],
        help="focused SPF/DKIM/DMARC view: what the authentication headers "
        "claim, alignment observations, offline (no DNS, no verification)",
    )
    p_auth.add_argument("file", help="path to the .eml / RFC 5322 message")
    p_auth.set_defaults(func=cmd_auth)

    p_urls = sub.add_parser(
        "urls",
        parents=[common],
        help="focused URL/domain inventory: URLs extracted from body "
        "text, HTML links, and headers, decomposed locally with "
        "observation-only analysis (never fetched, never resolved)",
    )
    p_urls.add_argument("file", help="path to the .eml / RFC 5322 message")
    p_urls.set_defaults(func=cmd_urls)

    p_attachments = sub.add_parser(
        "attachments",
        parents=[common],
        help="focused attachment inventory: magic-byte identification, "
        "declared-vs-identified type observations, archive contents by "
        "name only (in memory — never written to disk, never executed)",
    )
    p_attachments.add_argument("file", help="path to the .eml / RFC 5322 message")
    p_attachments.add_argument(
        "--hash",
        action="store_true",
        help="show full SHA-256 and MD5 hashes in human output "
        "(hashes are always present in --json)",
    )
    p_attachments.set_defaults(func=cmd_attachments)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    configure_logging()
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # --help / --version / usage errors: surface as an exit code,
        # never an exception, so main() is safe to call in-process.
        return int(exc.code or 0)
    if getattr(args, "verbose", False):
        configure_logging(verbose=True)
    cfg = config_mod.default_config()
    try:
        return int(args.func(args, cfg))
    except BrokenPipeError:  # pragma: no cover - terminal plumbing
        return EXIT_ERROR
    except Exception as exc:  # pragma: no cover - last-resort guard
        log.warning("unexpected failure: %s", exc)
        print(f"phishscope: unexpected error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
