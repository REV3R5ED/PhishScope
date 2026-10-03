"""Normalized authentication models for PhishScope v0.3.

Every model below describes what the message *headers claim* about
sender authentication — not what is true. SPF/DKIM/DMARC results are
taken from ``Authentication-Results`` / ``Received-SPF`` /
``DKIM-Signature`` headers exactly as written. PhishScope performs no
DNS lookups, so it never fetches SPF records, DKIM public keys, or
DMARC policies, and it never verifies a DKIM signature
cryptographically. A ``dkim=pass`` in an Authentication-Results header
means "some MTA claimed the signature verified", and the
:class:`DkimSignature` fields (``d=``, ``s=``, ``bh=`` …) record what
the signature *claims* — alignment observations are computed from
those claims only.

Observations are facts for the analyst (result triples, alignment,
conflicts, missing data) with the observed values as their basis —
never verdicts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from phishscope.core.models import ParserWarning, Provenance

# Result tokens seen in the wild (RFC 8601 §2.7 + common extensions).
# Anything unrecognized is preserved verbatim as an "unknown" result —
# never coerced into pass/fail.
KNOWN_RESULTS = frozenset(
    {
        "pass",
        "fail",
        "none",
        "neutral",
        "softfail",
        "temperror",
        "permerror",
        "policy",
    }
)


@dataclass
class AuthMethodResult:
    """One method result inside an Authentication-Results header.

    ``method`` is ``spf`` / ``dkim`` / ``dmarc`` (or another token as
    written). ``result`` is the token as written, lowercased
    (``pass``, ``fail``, ``none``, …). ``reason`` is the optional
    parenthesized comment. ``properties`` holds the ``key=value``
    pairs that followed the result (e.g. ``header.i``,
    ``envelope-from``, ``header.from``). ``authserv_id`` names the
    MTA that made the claim; ``raw`` is the unfolded header value
    verbatim.
    """

    method: str
    result: str
    reason: str | None
    properties: dict[str, str]
    authserv_id: str
    raw: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "result": self.result,
            "reason": self.reason,
            "properties": dict(self.properties),
            "authserv_id": self.authserv_id,
            "raw": self.raw,
        }


@dataclass
class DkimSignature:
    """What a ``DKIM-Signature`` header *claims* (never verified).

    Tag values are recorded verbatim. ``d`` is the signing domain,
    ``s`` the selector, ``bh`` the body-hash claim, ``h`` the list of
    signed header names, ``a`` the algorithm, ``c`` the
    canonicalization. Absent tags are None — the header simply did not
    claim them. No cryptographic verification is performed (offline).
    """

    d: str | None
    s: str | None
    a: str | None
    c: str | None
    h: list[str]
    bh: str | None
    raw: str
    other_tags: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "d": self.d,
            "s": self.s,
            "a": self.a,
            "c": self.c,
            "h": list(self.h),
            "bh": self.bh,
            "raw": self.raw,
            "other_tags": dict(self.other_tags),
            "cryptographically_verified": False,
            "verification_note": (
                "PhishScope is offline: no DNS lookups are performed, so "
                "the DKIM public key is never retrieved and the signature "
                "is never cryptographically verified. Fields above record "
                "what the signature claims."
            ),
        }


@dataclass
class ReceivedSpf:
    """One ``Received-SPF`` header, as written.

    ``result`` is the leading token (``pass``, ``fail``, ``neutral``,
    ``softfail``, ``none``, ``temperror``, ``permerror``, ``policy``,
    or verbatim if unrecognized). ``detail`` is the parenthesized
    explanation; ``raw`` the unfolded header value verbatim.
    """

    result: str
    detail: str | None
    raw: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "detail": self.detail,
            "raw": self.raw,
        }


@dataclass
class AuthObservation:
    """A single authentication observation (fact, not verdict).

    ``code`` is a stable machine-readable tag (e.g.
    ``spf-pass``); ``detail`` is a human sentence; ``basis`` holds
    the observed values that support it. Confidence framing: these
    describe metadata claims, not proof of anything.
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
class AuthAnalysis:
    """Normalized authentication view of one message.

    ``auth_results`` groups :class:`AuthMethodResult` per
    Authentication-Results header (in header order); ``dmarc`` holds
    the DMARC method results separately for convenience (they are
    also in ``auth_results``). Deterministic: :meth:`to_dict` emits
    fields in a fixed order.
    """

    evidence_id: str
    source_path: str
    sha256: str
    from_domain: str | None
    auth_results: list[AuthMethodResult]
    dkim_signatures: list[DkimSignature]
    received_spf: list[ReceivedSpf]
    observations: list[AuthObservation]
    parser_warnings: list[ParserWarning]
    provenance: Provenance

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source_path": self.source_path,
            "sha256": self.sha256,
            "from_domain": self.from_domain,
            "auth_results": [r.to_dict() for r in self.auth_results],
            "dkim_signatures": [s.to_dict() for s in self.dkim_signatures],
            "received_spf": [s.to_dict() for s in self.received_spf],
            "observations": [o.to_dict() for o in self.observations],
            "parser_warnings": [w.to_dict() for w in self.parser_warnings],
            "provenance": self.provenance.to_dict(),
        }
