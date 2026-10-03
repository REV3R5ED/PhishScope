"""Local URL decomposition for PhishScope v0.4.

Everything here is pure string/IP math on the observed URL — no
fetching, no DNS. :func:`decompose` splits a URL into its parts and
derives domain facts (IDNA forms, IP-literal detection, subdomain
depth, naive registered domain, shortener recognition, port
anomalies). :func:`dedup_key` gives the stable identity used to
merge repeated sightings of one URL.
"""

from __future__ import annotations

import ipaddress
import urllib.parse
from dataclasses import dataclass

from phishscope.urls.defang import defang_url, undefang_url

_DEFAULT_PORTS = {"http": 80, "https": 443}

# Well-known URL-shortening services (local list, observations only —
# the target is never expanded because PhishScope is offline).
_SHORTENERS = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "cutt.ly",
        "rb.gy",
        "rebrand.ly",
        "shorturl.at",
        "tiny.cc",
        "bl.ink",
        "lnkd.in",
        "s.id",
        "t.ly",
        "v.gd",
        "qr.ae",
        "shorte.st",
        "adf.ly",
    }
)


@dataclass
class DecomposedUrl:
    """Local decomposition of one observed URL."""

    url: str  # canonical exact value
    defanged: str
    scheme: str
    host: str
    host_unicode: str
    port: int | None
    path: str
    query_params: list[list[str]]
    fragment: str
    host_is_ip: bool
    ip_version: int | None
    punycode: bool
    userinfo: str | None
    registered_domain: str | None
    subdomain_depth: int
    tld: str | None
    nonstandard_port: bool
    shortener: bool
    invalid_port: bool


def _idna_decode(host: str) -> str:
    """Decode xn-- labels to Unicode for display; ASCII hosts unchanged."""
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return host


def _org_domain(host: str) -> str | None:
    """Naive organizational domain: last two labels.

    Documented approximation (same approach as v0.3's ``_org_domain``):
    without a public-suffix list — which cannot be fetched offline —
    ``co.uk``-style multi-label suffixes are not handled. The exact
    host is always reported alongside, so the analyst can judge.
    """
    labels = host.split(".")
    if len(labels) < 2:
        return None
    return ".".join(labels[-2:])


def decompose(raw_url: str) -> DecomposedUrl:
    """Decompose an observed URL locally; raises ValueError if unparseable.

    ``raw_url`` may still carry defanged spellings — it is normalized
    first. The canonical ``url`` is the undefanged exact value.
    """
    url = undefang_url(raw_url.strip())
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError as exc:
        raise ValueError(f"unparseable URL: {exc}") from exc
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme {scheme!r}")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("missing host")

    userinfo: str | None = None
    if parts.username or parts.password:
        userinfo = parts.username or ""
        if parts.password:
            userinfo += f":{parts.password}"

    port: int | None = None
    invalid_port = False
    try:
        port = parts.port
    except ValueError:
        # e.g. http://host:abc/ — recorded, not fatal.
        invalid_port = True

    punycode = any(label.startswith("xn--") for label in host.split("."))
    host_unicode = _idna_decode(host) if punycode else host

    host_is_ip = False
    ip_version: int | None = None
    try:
        ip_version = ipaddress.ip_address(host).version
        host_is_ip = True
    except ValueError:
        pass

    labels = host.split(".")
    tld = labels[-1] if len(labels) >= 2 and not host_is_ip else None
    registered = _org_domain(host) if not host_is_ip and len(labels) >= 2 else None
    depth = max(0, len(labels) - 2) if not host_is_ip else 0

    nonstandard_port = port is not None and port != _DEFAULT_PORTS.get(scheme, None)
    shortener = host in _SHORTENERS or (
        registered is not None and registered in _SHORTENERS
    )

    query_params = [
        [name, value]
        for name, value in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    ]

    return DecomposedUrl(
        url=url,
        defanged=defang_url(url),
        scheme=scheme,
        host=host,
        host_unicode=host_unicode,
        port=port,
        path=parts.path or "",
        query_params=query_params,
        fragment=parts.fragment or "",
        host_is_ip=host_is_ip,
        ip_version=ip_version,
        punycode=punycode,
        userinfo=userinfo,
        registered_domain=registered,
        subdomain_depth=depth,
        tld=tld,
        nonstandard_port=nonstandard_port,
        shortener=shortener,
        invalid_port=invalid_port,
    )


def dedup_key(d: DecomposedUrl) -> str:
    """Stable identity for merging repeated sightings of one URL.

    Lowercased scheme/host, default ports folded away, fragment
    dropped (fragments are client-side and never sent). Query strings
    are significant — different tracking parameters are different
    evidence.
    """
    netloc = d.host
    if d.port is not None and not (
        d.scheme in _DEFAULT_PORTS and d.port == _DEFAULT_PORTS[d.scheme]
    ):
        netloc = f"{netloc}:{d.port}"
    key = f"{d.scheme}://{netloc}{d.path}"
    if d.query_params:
        key += "?" + urllib.parse.urlencode(
            [(name, value) for name, value in d.query_params]
        )
    return key
