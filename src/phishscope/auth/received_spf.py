"""Parser for ``Received-SPF`` headers (RFC 8601 §2.5, tolerant).

Format: ``Received-SPF: <result> (<detail>) [key=value ...]`` — e.g.::

    Received-SPF: pass (mx.example.com: domain of alice@example.com
        designates 192.0.2.25 as permitted sender) client-ip=192.0.2.25;

The leading token is the SPF result as claimed by the receiving MTA;
the parenthesized text is the explanation. Parsing is tolerant:
whatever cannot be structured is kept verbatim in ``raw`` and
``detail``.

No DNS is performed — this records the receiving MTA's claim, not an
independent verification.
"""

from __future__ import annotations

from phishscope.auth.models import ReceivedSpf
from phishscope.core.models import ParserWarning


def parse_received_spf(value: str) -> tuple[ReceivedSpf | None, list[ParserWarning]]:
    """Parse one unfolded ``Received-SPF`` header value.

    Returns ``(ReceivedSpf_or_None, warnings)``.
    """
    warnings: list[ParserWarning] = []
    raw = value
    text = value.strip()
    if not text:
        warnings.append(
            ParserWarning(
                code="received-spf-empty",
                detail="Received-SPF header is empty",
                part=None,
            )
        )
        return None, warnings

    # Leading result token, then optional "(detail)".
    paren = text.find("(")
    if paren == -1:
        result = text.split()[0].lower() if text.split() else ""
        detail: str | None = None
    else:
        result = text[:paren].strip().split()[0].lower() if text[:paren].strip() else ""
        rest = text[paren:]
        depth = 0
        end = -1
        for i, ch in enumerate(rest):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        if end == -1:
            detail = rest[1:].strip() or None
            warnings.append(
                ParserWarning(
                    code="received-spf-unbalanced-paren",
                    detail="Received-SPF detail comment has unbalanced parentheses",
                    part=None,
                )
            )
        else:
            detail = rest[1:end].strip() or None

    if not result:
        warnings.append(
            ParserWarning(
                code="received-spf-no-result",
                detail="Received-SPF header has no result token",
                part=None,
            )
        )
        return None, warnings

    return ReceivedSpf(result=result, detail=detail, raw=raw), warnings
