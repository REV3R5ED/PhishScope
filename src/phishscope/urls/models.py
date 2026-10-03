"""Normalized URL models for PhishScope v0.4.

A :class:`UrlRecord` describes one *observed* URL exactly as found in
the message: the canonical exact value (undefanged — ``--json`` carries
this), a defanged display form for human output, a local
decomposition (scheme/host/port/path/query/fragment), IDNA forms, and
the sightings that produced it (which body part or header each copy
came from). Observations are facts with a basis, never verdicts.

Nothing here touches the network: no fetching, no DNS, no reputation
lookup. "Registered domain" is the documented PSL-free heuristic
(last two labels, same as v0.3's ``_org_domain``) and is always
reported alongside the exact host so the analyst can judge.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class UrlSource:
    """One sighting of a URL inside the message.

    ``kind`` is ``body-text`` (regex hit in a text part),
    ``html-href`` / ``html-src`` (structural attribute in an HTML
    part), ``html-anchor-text`` (the clickable text of an ``<a>`` whose
    href is the recorded URL), or ``header`` (a header value).
    ``detail`` names the part index (``"0.1"``) or header (``"List-
    Unsubscribe"``). ``defanged_in_source`` is True when the source
    text itself was defanged (``hxxp`` / ``[.]``) — common in shared
    threat reports; the canonical ``url`` is always the undefanged
    exact value. ``count`` is how many times the URL was seen at this
    exact location.
    """

    kind: str
    detail: str
    defanged_in_source: bool = False
    count: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "detail": self.detail,
            "defanged_in_source": self.defanged_in_source,
            "count": self.count,
        }


@dataclass
class UrlRecord:
    """One deduplicated observed URL with local decomposition."""

    url: str  # canonical exact value (undefanged)
    defanged: str  # display form for human output
    scheme: str
    host: str  # lowercased, as parsed
    host_unicode: str  # IDNA-decoded display form (== host when ASCII)
    port: int | None  # explicit port, or None
    path: str
    query_params: list[list[str]]  # [[name, value], ...]; values kept (evidence)
    fragment: str
    host_is_ip: bool
    ip_version: int | None  # 4 or 6 when host_is_ip
    punycode: bool  # any xn-- label present
    userinfo: str | None  # "user:pass" when present, else None
    registered_domain: str | None  # naive last-two-labels; None for IP/single-label
    subdomain_depth: int  # labels beyond the registered domain
    tld: str | None
    nonstandard_port: bool
    shortener: bool
    sources: list[UrlSource] = field(default_factory=list)
    observation_codes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "defanged": self.defanged,
            "scheme": self.scheme,
            "host": self.host,
            "host_unicode": self.host_unicode,
            "port": self.port,
            "path": self.path,
            "query_params": self.query_params,
            "fragment": self.fragment,
            "host_is_ip": self.host_is_ip,
            "ip_version": self.ip_version,
            "punycode": self.punycode,
            "userinfo": self.userinfo,
            "registered_domain": self.registered_domain,
            "subdomain_depth": self.subdomain_depth,
            "tld": self.tld,
            "nonstandard_port": self.nonstandard_port,
            "shortener": self.shortener,
            "sources": [s.to_dict() for s in self.sources],
            "observation_codes": self.observation_codes,
        }


@dataclass
class UrlObservation:
    """A single URL-forensics observation (fact, not verdict).

    ``code`` is a stable machine-readable tag (e.g.
    ``display-href-mismatch``); ``detail`` is a human sentence;
    ``basis`` holds the observed values that support it, always
    including the exact ``url``.
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
class UrlAnalysis:
    """Whole-message URL/domain analysis.

    Deterministic: :meth:`to_dict` emits fields in a fixed order and
    URLs are sorted by their canonical value, so identical input
    always yields identical JSON.
    """

    evidence_id: str
    source_path: str
    sha256: str
    urls: list[UrlRecord]
    observations: list[UrlObservation]
    parser_warnings: list[Any]
    provenance: Any

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source_path": self.source_path,
            "sha256": self.sha256,
            "url_count": len(self.urls),
            "urls": [u.to_dict() for u in sorted(self.urls, key=lambda r: r.url)],
            "observations": [o.to_dict() for o in self.observations],
            "parser_warnings": [
                w.to_dict() if hasattr(w, "to_dict") else w
                for w in self.parser_warnings
            ],
            "provenance": (
                self.provenance.to_dict()
                if hasattr(self.provenance, "to_dict")
                else self.provenance
            ),
        }
