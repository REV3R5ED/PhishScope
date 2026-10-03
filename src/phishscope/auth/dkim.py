"""Parser for ``DKIM-Signature`` headers (RFC 6376, tolerant).

Extracts the tag=value pairs (``v=``, ``a=``, ``b=``, ``bh=``,
``c=``, ``d=``, ``h=``, ``i=``, ``l=``, ``q=``, ``s=``, ``t=``,
``x=``, ``z=``). Values are recorded verbatim; the ``b=`` signature
blob is kept in ``other_tags`` (never truncated silently — the full
value is in ``raw`` anyway).

**Offline boundary:** PhishScope never retrieves the DKIM public key
(``s._domainkey.d`` TXT lookup) and never verifies the signature
cryptographically. :class:`DkimSignature` records what the header
*claims*. A signature that claims ``d=acme-invoices.net`` is an
observation that the signer *asserted* that domain — not proof the
assertion held.
"""

from __future__ import annotations

from phishscope.auth.models import DkimSignature
from phishscope.core.models import ParserWarning


def _split_tags(value: str) -> list[str]:
    """Split a DKIM-Signature value on ``;`` (tags never contain ``;``)."""
    return [seg for seg in value.split(";") if seg.strip()]


def parse_dkim_signature(
    value: str,
) -> tuple[DkimSignature | None, list[ParserWarning]]:
    """Parse one unfolded ``DKIM-Signature`` header value.

    Returns ``(signature_or_None, warnings)``. A header with no
    parseable tags yields ``None`` plus a warning.
    """
    warnings: list[ParserWarning] = []
    raw = value
    tags: dict[str, str] = {}
    for segment in _split_tags(value):
        if "=" not in segment:
            warnings.append(
                ParserWarning(
                    code="dkim-tag-no-equals",
                    detail="DKIM-Signature segment has no '=': "
                    f"{segment.strip()[:60]!r}",
                    part=None,
                )
            )
            continue
        name, _, val = segment.partition("=")
        name = name.strip().lower()
        if not name:
            warnings.append(
                ParserWarning(
                    code="dkim-tag-empty-name",
                    detail="DKIM-Signature segment has empty tag name: "
                    f"{segment.strip()[:60]!r}",
                    part=None,
                )
            )
            continue
        tags[name] = val.strip()

    if not tags:
        warnings.append(
            ParserWarning(
                code="dkim-no-tags",
                detail="DKIM-Signature header has no parseable tags",
                part=None,
            )
        )
        return None, warnings

    if "d" not in tags:
        warnings.append(
            ParserWarning(
                code="dkim-missing-d",
                detail="DKIM-Signature header has no d= (signing domain) tag",
                part=None,
            )
        )

    signed_headers = [
        h.strip().lower() for h in tags.get("h", "").split(":") if h.strip()
    ]
    # Tags with dedicated model fields; everything else (v=, b=, i=,
    # t=, …) is preserved verbatim in other_tags.
    known = {"d", "s", "a", "c", "h", "bh"}
    return (
        DkimSignature(
            d=tags.get("d") or None,
            s=tags.get("s") or None,
            a=tags.get("a") or None,
            c=tags.get("c") or None,
            h=signed_headers,
            bh=tags.get("bh") or None,
            raw=raw,
            other_tags={k: v for k, v in tags.items() if k not in known},
        ),
        warnings,
    )
