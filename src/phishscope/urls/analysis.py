"""Whole-message URL/domain analysis (v0.4).

:func:`analyze_urls` extracts URL candidates from raw message bytes
(body text, HTML attributes and text, all headers), normalizes and
deduplicates them, decomposes each locally (no network), and derives
observation-only facts. Attachment parts are skipped: a filename is
never treated as a URL.
"""

from __future__ import annotations

from phishscope import __version__
from phishscope.core.config import AppConfig
from phishscope.core.hashing import sha256_bytes
from phishscope.core.logging import utc_now_iso
from phishscope.core.models import ParserWarning, Provenance, evidence_id_for
from phishscope.urls.decompose import DecomposedUrl, decompose, dedup_key
from phishscope.urls.extract import UrlCandidate, extract_candidates
from phishscope.urls.models import (
    UrlAnalysis,
    UrlObservation,
    UrlRecord,
    UrlSource,
)
from phishscope.urls.observations import global_observations, observations_for

PARSER_NAME = "phishscope.urls"
PARSER_VERSION = "0.4.0"


def _merge_source(record: UrlRecord, candidate: UrlCandidate) -> None:
    """Add a sighting; repeated hits at the same location bump a count."""
    for existing in record.sources:
        if (
            existing.kind == candidate.kind
            and existing.detail == candidate.detail
            and existing.defanged_in_source == candidate.defanged_in_source
        ):
            existing.count += 1
            return
    record.sources.append(
        UrlSource(
            kind=candidate.kind,
            detail=candidate.detail,
            defanged_in_source=candidate.defanged_in_source,
        )
    )


def analyze_urls(raw: bytes, source_path: str, cfg: AppConfig) -> UrlAnalysis:
    """Analyze URLs/domains in a message from its raw bytes.

    ``cfg`` is accepted for the same safety-bound contract as the
    other parsers; analysis itself performs no network I/O.
    """
    digest = sha256_bytes(raw)
    warnings: list[ParserWarning] = []
    candidates = extract_candidates(raw, warnings)

    records: dict[str, UrlRecord] = {}
    decomposed: dict[str, DecomposedUrl] = {}
    # Per dedup key: anchor display texts and defanged sighting count,
    # accumulated before observation derivation.
    anchor_texts: dict[str, list[str]] = {}
    defanged_counts: dict[str, int] = {}

    for candidate in candidates:
        try:
            d: DecomposedUrl = decompose(candidate.text)
        except ValueError as exc:
            warnings.append(
                ParserWarning(
                    code="url-unparseable",
                    detail=f"skipping unparseable URL {candidate.text[:80]!r}: {exc}",
                )
            )
            continue
        key = dedup_key(d)
        record = records.get(key)
        if record is None:
            record = UrlRecord(
                url=d.url,
                defanged=d.defanged,
                scheme=d.scheme,
                host=d.host,
                host_unicode=d.host_unicode,
                port=d.port,
                path=d.path,
                query_params=d.query_params,
                fragment=d.fragment,
                host_is_ip=d.host_is_ip,
                ip_version=d.ip_version,
                punycode=d.punycode,
                userinfo=d.userinfo,
                registered_domain=d.registered_domain,
                subdomain_depth=d.subdomain_depth,
                tld=d.tld,
                nonstandard_port=d.nonstandard_port,
                shortener=d.shortener,
            )
            records[key] = record
            decomposed[key] = d
            anchor_texts[key] = []
            defanged_counts[key] = 0
        _merge_source(record, candidate)
        if candidate.anchor_text:
            anchor_texts[key].append(candidate.anchor_text)
        if candidate.defanged_in_source:
            defanged_counts[key] += 1

    observations: list[UrlObservation] = []
    for key, record in records.items():
        for obs in observations_for(
            decomposed[key], anchor_texts[key], defanged_counts[key]
        ):
            observations.append(obs)
            if obs.code not in record.observation_codes:
                record.observation_codes.append(obs.code)
    observations.extend(global_observations(len(records)))

    provenance = Provenance(
        parser_name=PARSER_NAME,
        parser_version=PARSER_VERSION,
        phishscope_version=__version__,
        analyzed_at_utc=utc_now_iso(),
    )
    return UrlAnalysis(
        evidence_id=evidence_id_for(digest),
        source_path=source_path,
        sha256=digest,
        urls=list(records.values()),
        observations=observations,
        parser_warnings=warnings,
        provenance=provenance,
    )
