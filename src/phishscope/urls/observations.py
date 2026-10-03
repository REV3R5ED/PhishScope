"""Observation-only URL/domain forensics for PhishScope v0.4.

Every function here returns facts with their basis — never verdicts.
A ``display-href-mismatch`` is a strong phishing signal in practice,
but v0.4 records it as an *observation*; heuristic judgments with
explicit limitations are v0.6 work. Query parameter *values* are
evidence and are kept verbatim (never redacted).
"""

from __future__ import annotations

from phishscope.urls.decompose import DecomposedUrl, decompose, dedup_key
from phishscope.urls.defang import clean_url_text, iter_url_candidates
from phishscope.urls.models import UrlObservation

_MANY_QUERY_PARAMS = 5
_DEEP_SUBDOMAIN = 4


def _display_key(raw: str) -> str | None:
    """Dedup key for anchor display text, when the text itself is a URL."""
    candidates = iter_url_candidates(raw.strip())
    if not candidates:
        return None
    candidate, _defanged = candidates[0]
    try:
        return dedup_key(decompose(clean_url_text(candidate)))
    except ValueError:
        return None


def observations_for(
    d: DecomposedUrl,
    anchor_texts: list[str],
    defanged_sightings: int,
) -> list[UrlObservation]:
    """Derive observation-only facts about one decomposed URL."""
    obs: list[UrlObservation] = []
    basis_url = {"url": d.url}

    if d.host_is_ip:
        obs.append(
            UrlObservation(
                code="ip-literal-host",
                detail=(
                    f"URL host is an IPv4/IPv6 literal ({d.host}), not a "
                    f"domain name — hostnames are easier to evaluate than "
                    f"bare addresses."
                ),
                basis={**basis_url, "host": d.host, "ip_version": d.ip_version},
            )
        )
    if d.userinfo:
        obs.append(
            UrlObservation(
                code="userinfo-present",
                detail=(
                    "URL embeds userinfo (user[:password]@host) — a classic "
                    "obfuscation shape; the true host follows the last '@'."
                ),
                basis={**basis_url, "userinfo": d.userinfo},
            )
        )
    if d.punycode:
        obs.append(
            UrlObservation(
                code="punycode-host",
                detail=(
                    f"host uses punycode ({d.host}); decoded form is "
                    f"{d.host_unicode!r} — compare visually for homographs."
                ),
                basis={
                    **basis_url,
                    "host": d.host,
                    "host_unicode": d.host_unicode,
                },
            )
        )
    if d.shortener:
        obs.append(
            UrlObservation(
                code="shortened-url",
                detail=(
                    f"host {d.host} is a known URL shortener; the target is "
                    "NOT expanded (PhishScope is offline) — the true "
                    "destination is unobserved."
                ),
                basis={**basis_url, "host": d.host},
            )
        )
    if d.nonstandard_port:
        obs.append(
            UrlObservation(
                code="nonstandard-port",
                detail=(
                    f"explicit port {d.port} on a {d.scheme} URL "
                    f"(default {80 if d.scheme == 'http' else 443})."
                ),
                basis={**basis_url, "port": d.port, "scheme": d.scheme},
            )
        )
    if d.invalid_port:
        obs.append(
            UrlObservation(
                code="invalid-port",
                detail="URL has an unparseable port component.",
                basis=basis_url,
            )
        )
    if d.scheme == "http":
        obs.append(
            UrlObservation(
                code="http-scheme",
                detail="URL uses plaintext http (no TLS).",
                basis=basis_url,
            )
        )
    if len(d.query_params) >= _MANY_QUERY_PARAMS:
        names = [name for name, _value in d.query_params]
        obs.append(
            UrlObservation(
                code="many-query-params",
                detail=(
                    f"URL carries {len(d.query_params)} query parameters "
                    f"({', '.join(names)}) — tracking/redirect candidate."
                ),
                basis={**basis_url, "param_names": names},
            )
        )
    if d.subdomain_depth >= _DEEP_SUBDOMAIN:
        obs.append(
            UrlObservation(
                code="deep-subdomain",
                detail=(
                    f"host has {d.subdomain_depth} subdomain levels beyond "
                    f"the registered domain ({d.registered_domain}) — "
                    "deep chains can bury the true domain."
                ),
                basis={
                    **basis_url,
                    "host": d.host,
                    "depth": d.subdomain_depth,
                    "registered_domain": d.registered_domain,
                },
            )
        )
    if defanged_sightings:
        obs.append(
            UrlObservation(
                code="defanged-in-source",
                detail=(
                    f"URL appeared defanged (hxxp/[.]/[:]) in "
                    f"{defanged_sightings} source sighting(s) — typical of "
                    "shared threat reports; canonical value is the "
                    "undefanged exact URL."
                ),
                basis={**basis_url, "sightings": defanged_sightings},
            )
        )
    for text in anchor_texts:
        display_key = _display_key(text)
        if display_key is None:
            continue  # anchor text is not a URL — nothing to compare
        href_key = dedup_key(d)
        if display_key != href_key:
            shown = clean_url_text(text.strip())
            obs.append(
                UrlObservation(
                    code="display-href-mismatch",
                    detail=(
                        "clickable text shows a different destination than "
                        "the link target: text shows "
                        f"{shown!r}, href goes to {d.url!r}."
                    ),
                    basis={
                        **basis_url,
                        "display_text": shown,
                        "href": d.url,
                    },
                )
            )
            break  # one mismatch observation per URL is enough
    return obs


def global_observations(url_count: int) -> list[UrlObservation]:
    """Message-level URL observations."""
    if url_count:
        return [
            UrlObservation(
                code="url-count",
                detail=(
                    f"{url_count} unique URL(s) observed in the message "
                    "(body, HTML attributes, headers)."
                ),
                basis={"url_count": url_count},
            )
        ]
    return [
        UrlObservation(
            code="no-urls",
            detail="no http(s) URLs observed in body text, HTML, or headers.",
            basis={"url_count": 0},
        )
    ]
