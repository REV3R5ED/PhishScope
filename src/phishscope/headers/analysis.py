"""Whole-message header analysis (v0.2).

:func:`analyze_headers` normalizes the routing/auth-relevant headers of
a message from its raw bytes and derives *observations* about the
Received chain. Observations are facts (hop counts, timestamp order,
private IPs, missing data) with the observed values as their basis —
never verdicts. Hostnames are never resolved and nothing is fetched;
every claim below is qualified by what the headers themselves say.
"""

from __future__ import annotations

import email.utils
import ipaddress
from datetime import timezone

from phishscope import __version__
from phishscope.core.config import AppConfig
from phishscope.core.hashing import sha256_bytes
from phishscope.core.logging import utc_now_iso
from phishscope.core.models import (
    Address,
    MessageDate,
    Provenance,
    evidence_id_for,
)
from phishscope.headers.models import HeaderAnalysis, HeaderObservation
from phishscope.headers.received import (
    ReceivedHop,
    parse_received_chain,
    unfold_headers,
)

PARSER_NAME = "phishscope.headers"
PARSER_VERSION = "0.2.0"

_LIST_HEADER_NAMES = (
    "list-id",
    "list-unsubscribe",
    "list-post",
    "list-owner",
    "list-help",
    "list-archive",
    "list-subscribe",
    "list-unsubscribe-post",
)


def _first_value(pairs: list[tuple[str, str]], name: str) -> str | None:
    for header_name, value in pairs:
        if header_name == name:
            return value or None
    return None


def _parse_address(value: str | None) -> Address | None:
    if not value:
        return None
    try:
        pairs = email.utils.getaddresses([value])
    except Exception:
        return None
    for display, addr_spec in pairs:
        if addr_spec:
            return Address(display_name=display, addr=addr_spec, raw=value)
    return None


def _parse_date(pairs: list[tuple[str, str]]) -> MessageDate:
    original = _first_value(pairs, "date")
    if original is None:
        return MessageDate(original=None, utc=None, valid=False)
    try:
        dt = email.utils.parsedate_to_datetime(original)
    except (TypeError, ValueError):
        return MessageDate(original=original, utc=None, valid=False)
    if dt is None or dt.tzinfo is None:
        return MessageDate(original=original, utc=None, valid=False)
    return MessageDate(
        original=original, utc=dt.astimezone(timezone.utc).isoformat(), valid=True
    )


def _is_private_ip(ip: str | None) -> bool:
    """True for internal-use addresses (RFC 1918, loopback, link-local,
    ULA, CGNAT) — the ranges that indicate non-public infrastructure.

    Documentation ranges (192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24, 2001:db8::/32) are *not* treated as private: they
    are public placeholders, and flagging them would be noise.
    """
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    nets: tuple[str, ...]
    if addr.version == 6:
        nets = ("::1/128", "fe80::/10", "fc00::/7")
    else:
        nets = (
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "100.64.0.0/10",
        )
    return any(addr in ipaddress.ip_network(net) for net in nets)


def _observe_chain(hops: list[ReceivedHop]) -> list[HeaderObservation]:
    """Derive observation-only facts about the Received chain."""
    observations: list[HeaderObservation] = []
    observations.append(
        HeaderObservation(
            code="hop-count",
            detail=f"Received chain has {len(hops)} hop(s) (oldest first).",
            basis={"hops": len(hops)},
        )
    )
    if not hops:
        observations.append(
            HeaderObservation(
                code="no-received-headers",
                detail="No Received headers present; routing path is unobserved.",
                basis={},
            )
        )
        return observations

    for hop in hops:
        if not hop.timestamp_valid:
            observations.append(
                HeaderObservation(
                    code="missing-timestamp",
                    detail=f"Hop {hop.position} has no parseable timestamp.",
                    basis={"hop": hop.position, "raw": hop.raw},
                )
            )
        for clause, ip in (("from", hop.from_ip), ("by", hop.by_ip)):
            if _is_private_ip(ip):
                observations.append(
                    HeaderObservation(
                        code="private-ip-hop",
                        detail=(
                            f"Hop {hop.position} {clause}-clause IP {ip} is a "
                            "private/loopback address (observed, not resolved)."
                        ),
                        basis={"hop": hop.position, "clause": clause, "ip": ip},
                    )
                )
        if hop.from_host and not hop.from_ip:
            observations.append(
                HeaderObservation(
                    code="unverifiable-from",
                    detail=(
                        f"Hop {hop.position} claims from-host "
                        f"'{hop.from_host}' with no bracketed IP — the claim "
                        "cannot be corroborated from the header alone "
                        "(no DNS performed)."
                    ),
                    basis={"hop": hop.position, "from_host": hop.from_host},
                )
            )

    # Timestamp order: each hop must be at/after the previous one.
    for prev, curr in zip(hops, hops[1:], strict=False):
        if (
            prev.timestamp_valid
            and curr.timestamp_valid
            and prev.timestamp_utc is not None
            and curr.timestamp_utc is not None
            and curr.timestamp_utc < prev.timestamp_utc
        ):
            observations.append(
                HeaderObservation(
                    code="timestamp-inversion",
                    detail=(
                        f"Hop {curr.position} timestamp "
                        f"({curr.timestamp_utc}) is earlier than hop "
                        f"{prev.position} ({prev.timestamp_utc}): clocks "
                        "disagree or a header was rewritten."
                    ),
                    basis={
                        "hop": curr.position,
                        "hop_timestamp": curr.timestamp_utc,
                        "previous_hop": prev.position,
                        "previous_timestamp": prev.timestamp_utc,
                    },
                )
            )
    return observations


def analyze_headers(raw: bytes, source_path: str, cfg: AppConfig) -> HeaderAnalysis:
    """Analyze routing/auth-relevant headers from raw message bytes.

    ``cfg`` is accepted for the same safety-bound contract as the v0.1
    parser (the 1 MB header block limit is enforced by the caller
    before parsing); analysis itself performs no network I/O.
    """
    digest = sha256_bytes(raw)
    pairs = unfold_headers(raw.split(b"\r\n\r\n")[0].split(b"\n\n")[0])
    hops, warnings = parse_received_chain(raw)
    observations = _observe_chain(hops)

    list_headers: dict[str, str] = {}
    for name in _LIST_HEADER_NAMES:
        value = _first_value(pairs, name)
        if value:
            list_headers[name] = value

    content_type = _first_value(pairs, "content-type")
    top_content_type = (
        content_type.split(";")[0].strip().lower() or None if content_type else None
    )

    x_originating_ip = _first_value(pairs, "x-originating-ip")
    x_sender_ip = _first_value(pairs, "x-sender-ip")
    for label, value in (
        ("x-originating-ip", x_originating_ip),
        ("x-sender-ip", x_sender_ip),
    ):
        if value:
            observations.append(
                HeaderObservation(
                    code="originating-ip-claim",
                    detail=f"Header {label} claims {value} (observed, not verified).",
                    basis={"header": label, "value": value},
                )
            )

    return HeaderAnalysis(
        evidence_id=evidence_id_for(digest),
        source_path=source_path,
        sha256=digest,
        return_path=_parse_address(_first_value(pairs, "return-path")),
        message_id=_first_value(pairs, "message-id"),
        date=_parse_date(pairs),
        received=hops,
        x_originating_ip=x_originating_ip,
        x_sender_ip=x_sender_ip,
        x_mailer=_first_value(pairs, "x-mailer"),
        user_agent=_first_value(pairs, "user-agent"),
        list_headers=list_headers,
        mime_version=_first_value(pairs, "mime-version"),
        top_content_type=top_content_type,
        observations=observations,
        parser_warnings=warnings,
        provenance=Provenance(
            parser_name=PARSER_NAME,
            parser_version=PARSER_VERSION,
            phishscope_version=__version__,
            analyzed_at_utc=utc_now_iso(),
        ),
    )
