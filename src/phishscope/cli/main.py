"""PhishScope CLI: ``phishscope analyze <message.eml>`` / ``overview <message.eml>``.

Every command renders human-readable text by default (``--json`` for
automation), uses structured exit codes (0 ok / 1 parser warnings /
2 error), and writes an audit record. Diagnostics go to stderr;
stdout carries only the requested output.

Forensic posture: the source file is only ever opened read-only, the
SHA-256 is computed before any parsing, and URLs in human output are
defanged so they cannot be followed by accident. ``--show-raw`` prints
the original bytes behind an explicit safety banner.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence
from typing import Any

from phishscope import __version__
from phishscope.core import config as config_mod
from phishscope.core.config import AppConfig
from phishscope.core.logging import audit_log, configure_logging, get_logger
from phishscope.core.models import NormalizedMessage
from phishscope.core.results import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, Result
from phishscope.parsers import safe_eml
from phishscope.parsers.safe_eml import ParseError

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


def cmd_analyze(args: argparse.Namespace, cfg: AppConfig) -> int:
    result, message, raw = _analyze(args.file, cfg)
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
    code = (
        EXIT_ERROR
        if result.status == "error"
        else EXIT_FINDINGS
        if result.message and result.message["parser_warnings"]
        else EXIT_OK
    )
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
    code = (
        EXIT_ERROR
        if result.status == "error"
        else EXIT_FINDINGS
        if result.message and result.message["parser_warnings"]
        else EXIT_OK
    )
    audit_log({"command": ["overview", args.file], "exit": code})
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
    p_analyze.set_defaults(func=cmd_analyze)

    p_overview = sub.add_parser(
        "overview",
        parents=[common],
        help="compact human-readable summary of a .eml message",
    )
    p_overview.add_argument("file", help="path to the .eml / RFC 5322 message")
    p_overview.set_defaults(func=cmd_overview)

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
