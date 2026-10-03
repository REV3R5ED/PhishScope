"""Whole-message authentication analysis (v0.3).

:func:`analyze_auth` normalizes the SPF/DKIM/DMARC-relevant headers of
a message from its raw bytes and derives *observations* — facts about
what the headers claim, never verdicts. The hard offline boundary:

* No DNS lookups of any kind (no SPF record fetching, no DKIM
  ``s._domainkey`` key retrieval, no DMARC policy fetching).
* DKIM signatures are parsed but never cryptographically verified;
  :class:`DkimSignature` records what the signature *claims*.
* DMARC "alignment" is computed from claimed domains only, reported
  as an observation with its basis, in both strict (exact match) and
  relaxed (organizational-domain match) modes. The relaxed
  organizational domain is a naive last-two-labels approximation —
  no public-suffix list is consulted offline — and the observation
  says so.

Metadata claims are not proof: an ``spf=pass`` means the MTA that
wrote the header *claimed* SPF passed, nothing more.
"""

from __future__ import annotations

import email.utils

from phishscope import __version__
from phishscope.auth.authentication_results import parse_authentication_results
from phishscope.auth.dkim import parse_dkim_signature
from phishscope.auth.models import (
    AuthAnalysis,
    AuthMethodResult,
    AuthObservation,
    DkimSignature,
    ReceivedSpf,
)
from phishscope.auth.received_spf import parse_received_spf
from phishscope.core.config import AppConfig
from phishscope.core.hashing import sha256_bytes
from phishscope.core.logging import utc_now_iso
from phishscope.core.models import ParserWarning, Provenance, evidence_id_for
from phishscope.headers.received import unfold_headers

PARSER_NAME = "phishscope.auth"
PARSER_VERSION = "0.3.0"


def _domain_of(value: str | None) -> str | None:
    """Extract the domain from an address or bare domain, lowercased.

    Accepts ``user@domain``, ``@domain``, or a bare ``domain``.
    Returns None for empty/unparseable input.
    """
    if not value:
        return None
    value = value.strip().lower().lstrip("@")
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    value = value.strip().rstrip(".")
    return value or None


def _org_domain(domain: str | None) -> str | None:
    """Naive organizational domain: last two labels.

    This is a documented approximation — without a public-suffix
    list (no network), ``co.uk``-style suffixes are not handled.
    Alignment observations always carry the exact domains as well,
    so the analyst can judge.
    """
    if not domain:
        return None
    labels = domain.split(".")
    if len(labels) < 2:
        return domain
    return ".".join(labels[-2:])


def _from_domain(pairs: list[tuple[str, str]]) -> str | None:
    """Domain of the RFC 5322 From address (claimed, not verified)."""
    for name, value in pairs:
        if name == "from":
            try:
                addrs = email.utils.getaddresses([value])
            except Exception:
                return None
            for _display, addr_spec in addrs:
                domain = _domain_of(addr_spec)
                if domain:
                    return domain
            return None
    return None


def _props_domain(result: AuthMethodResult, *keys: str) -> str | None:
    """First domain found under the given property keys.

    The conventional ``none`` placeholder (e.g. ``header.d=none``)
    means "no value" and is treated as missing.
    """
    for key in keys:
        if key in result.properties:
            domain = _domain_of(result.properties[key])
            if domain and domain != "none":
                return domain
    return None


def _alignment(
    claimed: str | None, reference: str | None
) -> tuple[bool | None, bool | None]:
    """(strict, relaxed) alignment of two claimed domains.

    None when either side is missing (alignment unobservable).
    """
    if not claimed or not reference:
        return None, None
    strict = claimed == reference
    relaxed = _org_domain(claimed) == _org_domain(reference)
    return strict, relaxed


def _observe_results(
    results: list[AuthMethodResult], observations: list[AuthObservation]
) -> None:
    """One observation per method result, as claimed."""
    for r in results:
        domain = _props_domain(
            r,
            "header.i",
            "header.d",
            "header.from",
            "smtp.mailfrom",
            "envelope-from",
            "mailfrom",
        )
        detail = f"{r.method}={r.result}"
        if r.authserv_id and r.authserv_id != "unknown":
            detail += f" (claimed by {r.authserv_id})"
        if domain:
            detail += f" for {domain}"
        if r.reason:
            detail += f" — {r.reason}"
        observations.append(
            AuthObservation(
                code=f"{r.method}-{r.result}",
                detail=detail + ".",
                basis={
                    "method": r.method,
                    "result": r.result,
                    "authserv_id": r.authserv_id,
                    "domain": domain,
                    "reason": r.reason,
                    "properties": dict(r.properties),
                },
            )
        )


def _observe_conflicts(
    results: list[AuthMethodResult], observations: list[AuthObservation]
) -> None:
    """Flag when Authentication-Results headers disagree per method."""
    by_method: dict[str, dict[str, set[str]]] = {}
    for r in results:
        by_method.setdefault(r.method, {}).setdefault(r.result, set()).add(
            r.authserv_id
        )
    for method, result_map in sorted(by_method.items()):
        if len(result_map) > 1:
            summary = "; ".join(
                f"{res} (by {', '.join(sorted(ids))})"
                for res, ids in sorted(result_map.items())
            )
            observations.append(
                AuthObservation(
                    code="conflicting-auth-results",
                    detail=(
                        f"Authentication-Results headers disagree on {method}: "
                        f"{summary}. Different hops applied different "
                        "policies — treat each claim separately."
                    ),
                    basis={
                        "method": method,
                        "results": {
                            res: sorted(ids) for res, ids in result_map.items()
                        },
                    },
                )
            )


def _observe_dkim_signatures(
    signatures: list[DkimSignature], observations: list[AuthObservation]
) -> None:
    """Record each DKIM-Signature claim (never verified)."""
    for sig in signatures:
        observations.append(
            AuthObservation(
                code="dkim-signature-present",
                detail=(
                    f"DKIM-Signature present: d={sig.d or '<missing>'}, "
                    f"s={sig.s or '<missing>'}, a={sig.a or '<missing>'}; "
                    "NOT cryptographically verified (offline — no DNS, "
                    "no key retrieval). The fields record what the "
                    "signature claims."
                ),
                basis={
                    "d": sig.d,
                    "s": sig.s,
                    "a": sig.a,
                    "c": sig.c,
                    "signed_headers": list(sig.h),
                    "body_hash_claim": sig.bh,
                },
            )
        )
    if not signatures:
        observations.append(
            AuthObservation(
                code="dkim-signature-absent",
                detail=(
                    "No DKIM-Signature header present: the message carries "
                    "no DKIM signer claim of its own."
                ),
                basis={},
            )
        )


def _observe_alignment(
    results: list[AuthMethodResult],
    signatures: list[DkimSignature],
    from_domain: str | None,
    observations: list[AuthObservation],
) -> None:
    """DMARC-style alignment as observations (claims only)."""
    spf_domains: set[str] = {
        d
        for d in (
            _props_domain(r, "smtp.mailfrom", "envelope-from", "mailfrom")
            for r in results
            if r.method == "spf"
        )
        if d is not None
    }
    dkim_domains: set[str] = {
        d
        for d in (
            _props_domain(r, "header.i", "header.d")
            for r in results
            if r.method == "dkim"
        )
        if d is not None
    } | {s.d for s in signatures if s.d}

    for label, domains in (("spf", spf_domains), ("dkim", dkim_domains)):
        for domain in sorted(domains):
            strict, relaxed = _alignment(domain, from_domain)
            if strict is None:
                observations.append(
                    AuthObservation(
                        code=f"{label}-alignment-unknown",
                        detail=(
                            f"{label} alignment unobservable: "
                            f"{label} domain {domain!r} but no From domain "
                            "to compare against."
                        ),
                        basis={f"{label}_domain": domain},
                    )
                )
                continue
            state = (
                "aligned" if strict else ("relaxed-aligned" if relaxed else "unaligned")
            )
            observations.append(
                AuthObservation(
                    code=f"{label}-alignment-{state}",
                    detail=(
                        f"{label} domain {domain!r} vs From domain "
                        f"{from_domain!r}: {state} "
                        f"(strict={'yes' if strict else 'no'}, "
                        f"relaxed={'yes' if relaxed else 'no'}; relaxed uses "
                        "naive last-two-labels, no public-suffix list)."
                    ),
                    basis={
                        f"{label}_domain": domain,
                        "from_domain": from_domain,
                        "strict": strict,
                        "relaxed": relaxed,
                    },
                )
            )


def _observe_spf_crosscheck(
    results: list[AuthMethodResult],
    received_spf: list[ReceivedSpf],
    observations: list[AuthObservation],
) -> None:
    """Compare Received-SPF claims against Authentication-Results SPF."""
    ar_spf = {r.result for r in results if r.method == "spf"}
    for entry in received_spf:
        observations.append(
            AuthObservation(
                code=f"received-spf-{entry.result}",
                detail=(
                    f"Received-SPF claims spf={entry.result}"
                    + (f" — {entry.detail}" if entry.detail else "")
                    + "."
                ),
                basis={"result": entry.result, "detail": entry.detail},
            )
        )
        if ar_spf and entry.result not in ar_spf:
            observations.append(
                AuthObservation(
                    code="spf-claim-disagreement",
                    detail=(
                        f"Received-SPF claims '{entry.result}' but "
                        "Authentication-Results SPF claims "
                        f"{sorted(ar_spf)}: the receiving hops disagree."
                    ),
                    basis={
                        "received_spf": entry.result,
                        "auth_results_spf": sorted(ar_spf),
                    },
                )
            )


def analyze_auth(raw: bytes, source_path: str, cfg: AppConfig) -> AuthAnalysis:
    """Analyze SPF/DKIM/DMARC-relevant headers from raw message bytes.

    ``cfg`` is accepted for the same safety-bound contract as the
    other parsers; analysis itself performs no network I/O.
    """
    digest = sha256_bytes(raw)
    pairs = unfold_headers(raw.split(b"\r\n\r\n")[0].split(b"\n\n")[0])

    warnings: list[ParserWarning] = []
    results: list[AuthMethodResult] = []
    signatures: list[DkimSignature] = []
    received_spf: list[ReceivedSpf] = []

    for name, value in pairs:
        if name == "authentication-results":
            _authserv, parsed, warns = parse_authentication_results(value)
            results.extend(parsed)
            warnings.extend(warns)
        elif name == "dkim-signature":
            sig, warns = parse_dkim_signature(value)
            if sig is not None:
                signatures.append(sig)
            warnings.extend(warns)
        elif name == "received-spf":
            entry, warns = parse_received_spf(value)
            if entry is not None:
                received_spf.append(entry)
            warnings.extend(warns)

    from_domain = _from_domain(pairs)

    observations: list[AuthObservation] = []
    if not results and not signatures and not received_spf:
        observations.append(
            AuthObservation(
                code="no-auth-headers",
                detail=(
                    "No Authentication-Results, DKIM-Signature, or "
                    "Received-SPF headers present: authentication is "
                    "unobserved (not 'failed')."
                ),
                basis={},
            )
        )
    _observe_results(results, observations)
    _observe_conflicts(results, observations)
    _observe_dkim_signatures(signatures, observations)
    _observe_alignment(results, signatures, from_domain, observations)
    _observe_spf_crosscheck(results, received_spf, observations)

    return AuthAnalysis(
        evidence_id=evidence_id_for(digest),
        source_path=source_path,
        sha256=digest,
        from_domain=from_domain,
        auth_results=results,
        dkim_signatures=signatures,
        received_spf=received_spf,
        observations=observations,
        parser_warnings=warnings,
        provenance=Provenance(
            parser_name=PARSER_NAME,
            parser_version=PARSER_VERSION,
            phishscope_version=__version__,
            analyzed_at_utc=utc_now_iso(),
        ),
    )
