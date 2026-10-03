"""Parser for ``Authentication-Results`` headers (RFC 8601, tolerant).

Parses the results exactly as written: authserv-id, per-method
result tokens, optional reasons, and ``ptype.property=value`` pairs
(``smtp.mailfrom``, ``header.i``, ``header.from``, …). Malformed
headers produce :class:`ParserWarning` entries, never exceptions.

No network I/O of any kind — results are claims made by the MTA
that added the header.
"""

from __future__ import annotations

import re

from phishscope.auth.models import KNOWN_RESULTS, AuthMethodResult
from phishscope.core.models import ParserWarning

_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def _split_top_level(value: str, sep: str = ";") -> list[str]:
    """Split on ``sep`` ignoring separators inside ``(...)`` comments."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in value:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if ch == sep and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return parts


def _extract_reasons(clause: str) -> tuple[str, str | None]:
    """Pull the first ``(...)`` comment out of a clause.

    Returns ``(clause_without_reason, reason_text_or_None)``. Nested
    parentheses are kept verbatim inside the reason.
    """
    start = clause.find("(")
    if start == -1:
        return clause, None
    depth = 0
    for i in range(start, len(clause)):
        if clause[i] == "(":
            depth += 1
        elif clause[i] == ")":
            depth -= 1
            if depth == 0:
                reason = clause[start + 1 : i].strip() or None
                rest = (clause[:start] + " " + clause[i + 1 :]).strip()
                return rest, reason
    # Unbalanced paren: treat the rest as the reason, keep parsing.
    return clause[:start].strip(), clause[start + 1 :].strip() or None


def _parse_clause(
    clause: str, authserv_id: str, raw: str, warnings: list[ParserWarning]
) -> AuthMethodResult | None:
    """Parse one ``method=result [props]`` clause."""
    clause = clause.strip()
    if not clause:
        return None
    if "=" not in clause:
        warnings.append(
            ParserWarning(
                code="auth-results-clause-no-equals",
                detail=f"Authentication-Results clause has no '=': {clause[:80]!r}",
                part=None,
            )
        )
        return None
    method, _, rest = clause.partition("=")
    method = method.strip().lower()
    if not method or not _TOKEN_RE.fullmatch(method):
        warnings.append(
            ParserWarning(
                code="auth-results-bad-method",
                detail="Authentication-Results clause has invalid "
                f"method: {clause[:80]!r}",
                part=None,
            )
        )
        return None
    rest = rest.strip()
    rest, reason = _extract_reasons(rest)
    tokens = rest.split()
    result = tokens[0].lower() if tokens else ""
    if not result:
        warnings.append(
            ParserWarning(
                code="auth-results-missing-result",
                detail=f"Authentication-Results clause '{method}' has no result token",
                part=None,
            )
        )
        return None
    properties: dict[str, str] = {}
    for token in tokens[1:]:
        if "=" not in token:
            continue
        key, _, val = token.partition("=")
        key = key.strip().lower()
        if key:
            properties[key] = val.strip()
    return AuthMethodResult(
        method=method,
        result=result,
        reason=reason,
        properties=properties,
        authserv_id=authserv_id,
        raw=raw,
    )


def parse_authentication_results(
    value: str,
) -> tuple[str, list[AuthMethodResult], list[ParserWarning]]:
    """Parse one unfolded ``Authentication-Results`` header value.

    Returns ``(authserv_id, results, warnings)``. ``results`` may be
    empty (header present but unparseable); ``authserv_id`` is the
    text before the first ``;`` (or the whole value when there is
    none).
    """
    warnings: list[ParserWarning] = []
    raw = value
    segments = _split_top_level(value)
    first = segments[0].strip()
    if len(segments) == 1:
        # No method clauses at all: the whole header is an authserv-id
        # claim (or garbage). Record it, warn, return no results.
        warnings.append(
            ParserWarning(
                code="auth-results-no-clauses",
                detail=(
                    "Authentication-Results header has no method clauses: "
                    f"{first[:80]!r}"
                ),
                part=None,
            )
        )
        return first or "unknown", [], warnings
    authserv_id = first.split()[0] if first else "unknown"
    results: list[AuthMethodResult] = []
    for clause in segments[1:]:
        parsed = _parse_clause(clause, authserv_id, raw, warnings)
        if parsed is not None:
            results.append(parsed)
    return authserv_id, results, warnings


def known_result_token(result: str) -> bool:
    """True when ``result`` is a recognized RFC 8601 result token."""
    return result.lower() in KNOWN_RESULTS
