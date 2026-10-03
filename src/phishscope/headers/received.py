"""Tolerant parser for ``Received`` header chains (v0.2).

Received headers are prepended by each handling MTA, so in the raw
message they appear newest-first; this module reverses them into
oldest-to-newest hop order. Parsing is best-effort and never raises
for malformed input: unparseable clauses become ``None`` slots and a
recorded :class:`ParserWarning`, and the verbatim header value is
always kept on the hop's ``raw`` field.

No network is ever touched — bracketed IPs are validated locally
with the stdlib ``ipaddress`` module and hostnames are never
resolved.
"""

from __future__ import annotations

import email.utils
import ipaddress
import re
from datetime import timezone

from phishscope.core.models import ParserWarning
from phishscope.headers.models import ReceivedHop

# Clause keywords that segment a Received value (RFC 5321 §4.4 order
# is from / by / with / id, but real-world headers vary).
_CLAUSE_RE = re.compile(r"\b(from|by|with|id|for|via)\b", re.IGNORECASE)
_BRACKET_RE = re.compile(r"\[([^\[\]]+)\]")
_TOKEN_RE = re.compile(r"\S+")


def unfold_headers(head: bytes) -> list[tuple[str, str]]:
    """Unfold the raw header block into ``(name, value)`` pairs.

    Continuation lines (leading whitespace) are joined with a single
    space. Order is preserved; repeated headers appear repeatedly.
    """
    unfolded: list[bytes] = []
    current: bytes | None = None
    for line in head.split(b"\n"):
        line = line.rstrip(b"\r")
        if line[:1] in b" \t" and current is not None:
            current += b" " + line.strip()
        else:
            if current is not None:
                unfolded.append(current)
            current = line
    if current is not None:
        unfolded.append(current)
    pairs: list[tuple[str, str]] = []
    for header_line in unfolded:
        name, sep, value = header_line.partition(b":")
        if not sep:
            continue
        pairs.append(
            (
                name.strip().decode("ascii", "replace").lower(),
                value.strip().decode("utf-8", "replace"),
            )
        )
    return pairs


def _split_head(raw: bytes) -> bytes:
    """Return the raw header block (everything before the blank line)."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            return raw[:idx]
    return raw


def _clean_ip(token: str) -> str | None:
    """Return the token as a valid IP string, else None (local only)."""
    candidate = token.strip()
    if candidate[:5].lower() == "ipv6:":
        candidate = candidate[5:]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _split_clauses(body: str) -> list[tuple[str, str]]:
    """Split a Received body into ``(keyword, segment)`` pairs."""
    matches = list(_CLAUSE_RE.finditer(body))
    segments: list[tuple[str, str]] = []
    for i, match in enumerate(matches):
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        segments.append((match.group(1).lower(), body[start:end]))
    return segments


def _first_token(segment: str) -> str | None:
    match = _TOKEN_RE.search(segment)
    return match.group(0) if match else None


def _host_and_ip(segment: str) -> tuple[str | None, str | None]:
    """Best-effort ``(host, ip)`` from a from/by clause segment.

    The host is the first token; the IP is the first bracketed literal
    that parses as an IPv4/IPv6 address (a bare IP token with no
    brackets counts too).
    """
    host: str | None = None
    ip: str | None = None
    token = _first_token(segment)
    if token:
        stripped = token.strip("[]")
        as_ip = _clean_ip(stripped)
        if as_ip is not None:
            ip = as_ip
        else:
            host = token
    for bracketed in _BRACKET_RE.findall(segment):
        as_ip = _clean_ip(bracketed)
        if as_ip is not None:
            ip = as_ip
            break
    return host, ip


def _parse_timestamp(text: str) -> tuple[str | None, str | None, bool]:
    """Parse the timestamp after the final ``;``.

    Returns ``(original, utc_iso, valid)``. A timezone is never
    invented: naive or unparseable timestamps keep ``utc`` None.
    """
    original = text.strip() or None
    if not original:
        return None, None, False
    try:
        dt = email.utils.parsedate_to_datetime(original)
    except (TypeError, ValueError):
        return original, None, False
    if dt is None or dt.tzinfo is None:
        return original, None, False
    return original, dt.astimezone(timezone.utc).isoformat(), True


def parse_received_value(
    value: str, position: int
) -> tuple[ReceivedHop, list[ParserWarning]]:
    """Parse one unfolded Received value into a hop (never raises)."""
    warnings: list[ParserWarning] = []
    raw = value.strip()
    from_host = from_ip = by_host = by_ip = None
    with_protocol: str | None = None
    hop_id: str | None = None

    if ";" in raw:
        body, _, stamp_text = raw.rpartition(";")
    else:
        body, stamp_text = raw, ""
    if not stamp_text.strip():
        warnings.append(
            ParserWarning(
                code="received-no-timestamp",
                detail=f"Received hop {position} has no parseable timestamp",
            )
        )
    timestamp_original, timestamp_utc, timestamp_valid = _parse_timestamp(stamp_text)
    if stamp_text.strip() and not timestamp_valid:
        warnings.append(
            ParserWarning(
                code="received-bad-timestamp",
                detail=f"Received hop {position} timestamp could not be parsed",
            )
        )

    for keyword, segment in _split_clauses(body):
        if keyword == "from":
            from_host, from_ip = _host_and_ip(segment)
        elif keyword == "by":
            by_host, by_ip = _host_and_ip(segment)
        elif keyword == "with":
            token = _first_token(segment)
            with_protocol = token if token else None
        elif keyword == "id":
            token = _first_token(segment)
            hop_id = token.rstrip(";") if token else None

    if not any([from_host, from_ip, by_host, by_ip, with_protocol, hop_id]):
        warnings.append(
            ParserWarning(
                code="received-unparseable",
                detail=f"Received hop {position} yielded no recognizable clauses",
            )
        )

    hop = ReceivedHop(
        position=position,
        from_host=from_host,
        from_ip=from_ip,
        by_host=by_host,
        by_ip=by_ip,
        with_protocol=with_protocol,
        hop_id=hop_id,
        timestamp_original=timestamp_original,
        timestamp_utc=timestamp_utc,
        timestamp_valid=timestamp_valid,
        raw=raw,
    )
    return hop, warnings


def parse_received_chain(raw: bytes) -> tuple[list[ReceivedHop], list[ParserWarning]]:
    """Parse all Received headers into hops, oldest first.

    Returns ``(hops, warnings)``. An empty hop list is a valid result
    (messages can carry no Received headers at all).
    """
    head = _split_head(raw)
    values = [value for name, value in unfold_headers(head) if name == "received"]
    hops: list[ReceivedHop] = []
    warnings: list[ParserWarning] = []
    # Received headers are prepended newest-first; reverse for oldest-first.
    for position, value in enumerate(reversed(values)):
        hop, hop_warnings = parse_received_value(value, position)
        hops.append(hop)
        warnings.extend(hop_warnings)
    return hops, warnings
