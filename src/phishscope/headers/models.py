"""Normalized header models for PhishScope v0.2.

The models describe what the message *headers claim*. A Received hop
records the from/by hostnames and IPs exactly as written — a bracketed
IP is an observed literal, a bare hostname is an unverified claim
(no DNS is ever performed to check it). Timestamps keep the verbatim
original alongside the UTC normalization; unparseable or naive
timestamps keep ``utc`` as None.

Observations are facts for the analyst (hop counts, timestamp order,
private IPs, missing data). They carry a ``basis`` of observed values
and never a verdict — phishing judgments belong to humans (and, later,
to the v0.6 heuristics with explicit limitations).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from phishscope.core.models import Address, MessageDate, ParserWarning, Provenance


@dataclass
class ReceivedHop:
    """One hop of the Received chain.

    ``position`` 0 is the oldest hop (the first MTA that handled the
    message); the last position is the final delivery hop. ``raw`` is
    the unfolded header value verbatim — the slots below are the
    best-effort parse of that claim.
    """

    position: int
    from_host: str | None
    from_ip: str | None
    by_host: str | None
    by_ip: str | None
    with_protocol: str | None
    hop_id: str | None
    timestamp_original: str | None
    timestamp_utc: str | None
    timestamp_valid: bool
    raw: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "position": self.position,
            "from_host": self.from_host,
            "from_ip": self.from_ip,
            "by_host": self.by_host,
            "by_ip": self.by_ip,
            "with_protocol": self.with_protocol,
            "hop_id": self.hop_id,
            "timestamp_original": self.timestamp_original,
            "timestamp_utc": self.timestamp_utc,
            "timestamp_valid": self.timestamp_valid,
            "raw": self.raw,
        }


@dataclass
class HeaderObservation:
    """A single header-forensics observation (fact, not verdict).

    ``code`` is a stable machine-readable tag (e.g.
    ``timestamp-inversion``); ``detail`` is a human sentence; ``basis``
    holds the observed values that support it.
    """

    code: str
    detail: str
    basis: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "detail": self.detail,
            "basis": self.basis,
        }


@dataclass
class HeaderAnalysis:
    """Normalized routing/auth-relevant headers of one message.

    ``received`` is ordered oldest-to-newest. ``observations`` are
    derived facts about the chain; ``parser_warnings`` are non-fatal
    parse problems. Deterministic: :meth:`to_dict` emits fields in a
    fixed order.
    """

    evidence_id: str
    source_path: str
    sha256: str
    return_path: Address | None
    message_id: str | None
    date: MessageDate
    received: list[ReceivedHop]
    x_originating_ip: str | None
    x_sender_ip: str | None
    x_mailer: str | None
    user_agent: str | None
    list_headers: dict[str, str]
    mime_version: str | None
    top_content_type: str | None
    observations: list[HeaderObservation]
    parser_warnings: list[ParserWarning]
    provenance: Provenance

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source_path": self.source_path,
            "sha256": self.sha256,
            "return_path": self.return_path.to_dict() if self.return_path else None,
            "message_id": self.message_id,
            "date": self.date.to_dict(),
            "received": [h.to_dict() for h in self.received],
            "x_originating_ip": self.x_originating_ip,
            "x_sender_ip": self.x_sender_ip,
            "x_mailer": self.x_mailer,
            "user_agent": self.user_agent,
            "list_headers": dict(self.list_headers),
            "mime_version": self.mime_version,
            "top_content_type": self.top_content_type,
            "observations": [o.to_dict() for o in self.observations],
            "parser_warnings": [w.to_dict() for w in self.parser_warnings],
            "provenance": self.provenance.to_dict(),
        }
