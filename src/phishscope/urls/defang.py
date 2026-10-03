"""Defang / undefang helpers for PhishScope v0.4.

Human-readable output must never contain a clickable URL, so URLs are
displayed defanged (``hxxp://example[.]com/x``). ``--json`` always
carries the exact (undefanged) value for tooling. Defanged URLs in the
*source* message (common in shared threat reports: ``hxxp``,
``[.]``, ``[:]``) are recognized, recorded as an observation, and
normalized to their exact form for the canonical record.
"""

from __future__ import annotations

import re

# Matches http(s) URLs, including the common defanged spellings found
# in shared reports: hxxp://, hxxps://, http[:]//, and hosts written
# with [.] instead of dots. A scheme separator (":" or "[:]" followed
# by "//") is required so bare words like "https" never match.
_URL_RE = re.compile(r"(?:hxxps?|https?)(?:\[:\]|:)//[^\s\"'<>]+", re.IGNORECASE)

_DEFANGED_MARKERS = ("hxxp", "[.]", "[:]")


def looks_defanged(text: str) -> bool:
    """True when the text uses defanged URL spellings."""
    lowered = text.lower()
    return any(marker in lowered for marker in _DEFANGED_MARKERS)


def defang_url(url: str) -> str:
    """Render a URL defanged for safe human display.

    ``http://``/``https://`` become ``hxxp://``/``hxxps://`` and every
    ``.`` becomes ``[.]``. Idempotent for already-defanged input.
    """
    lowered = url.lower()
    if lowered.startswith("https://"):
        rest = url[len("https://") :]
        return "hxxps://" + rest.replace(".", "[.]")
    if lowered.startswith("http://"):
        rest = url[len("http://") :]
        return "hxxp://" + rest.replace(".", "[.]")
    # Already defanged (or an unknown scheme): dot-defang only, and
    # do not double-defang existing [.] markers.
    return re.sub(r"\.(?!\])", "[.]", url)


def undefang_url(text: str) -> str:
    """Restore the exact URL from a possibly-defanged spelling.

    Reverses ``hxxp``→``http``, ``hxxps``→``https``, ``[.]``→``.``,
    and ``[:]``→``:``. Plain URLs pass through unchanged.
    """
    out = text
    # Scheme first (case-insensitive), before dot restoration.
    out = re.sub(r"^hxxps(?=://|\[:\])", "https", out, flags=re.IGNORECASE)
    out = re.sub(r"^hxxp(?=://|\[:\])", "http", out, flags=re.IGNORECASE)
    out = out.replace("[:]", ":").replace("[.]", ".")
    return out


def clean_url_text(text: str) -> str:
    """Strip trailing sentence punctuation from a regex-extracted URL.

    Removes trailing ``.,;:!?`` and one layer of unbalanced closing
    brackets/quotes. Balanced pairs (e.g. Wikipedia-style
    ``.../Article_(disambiguation)``) are preserved.
    """
    url = text
    while url and url[-1] in ".,;:!?":
        url = url[:-1]
    # Unbalanced closers: strip one trailing ), ], } or quote when the
    # matching opener does not appear in the URL.
    pairs = {")": "(", "]": "[", "}": "{", "'": "'", '"': '"'}
    while url and url[-1] in pairs:
        closer = url[-1]
        opener = pairs[closer]
        if opener == closer:
            url = url[:-1]
            continue
        if url.count(opener) < url.count(closer):
            url = url[:-1]
            continue
        break
    return url


def iter_url_candidates(text: str) -> list[tuple[str, bool]]:
    """Yield ``(candidate, defanged_in_source)`` for URL-like strings.

    Candidates are cleaned of trailing punctuation. The returned
    candidate keeps its original (possibly defanged) spelling; callers
    normalize with :func:`undefang_url`.
    """
    found: list[tuple[str, bool]] = []
    for match in _URL_RE.finditer(text):
        raw = clean_url_text(match.group(0))
        if not raw:
            continue
        found.append((raw, looks_defanged(raw)))
    return found
