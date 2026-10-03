"""URL candidate extraction from raw message bytes (v0.4).

Read-only structural extraction — nothing renders, nothing fetches,
nothing executes:

- ``text/plain`` body parts: URL regex over the decoded text.
- ``text/html`` body parts: structural parse with stdlib
  ``html.parser`` — ``href``/``src`` attributes are recorded with
  their tag, anchor display text is captured for display-vs-
  destination comparison, and visible text nodes are regex-scanned.
  The HTML is never rendered.
- All header values: URL regex (covers ``List-Unsubscribe``,
  ``Content-Location``, etc.).
- Attachment parts are skipped entirely: an attachment filename is
  never treated as a URL.

Extraction caps (documented, local to this module): at most 50 text
parts are scanned, 1 MB of decoded text per part, 2,000 URL
candidates total. Hitting a cap records a warning; the message is
still analyzed.
"""

from __future__ import annotations

import email
from dataclasses import dataclass
from email.message import Message
from html.parser import HTMLParser

from phishscope.core.models import ParserWarning
from phishscope.urls.defang import iter_url_candidates

MAX_TEXT_PARTS = 50
MAX_TEXT_BYTES_PER_PART = 1_000_000
MAX_URL_CANDIDATES = 2000


@dataclass
class UrlCandidate:
    """One raw sighting, before normalization and dedup."""

    text: str  # the URL-like string as found (maybe defanged)
    kind: str  # body-text | html-href | html-src | html-text | header
    detail: str  # part index ("0.1") or header name
    defanged_in_source: bool
    anchor_href: str | None = None  # for html-text inside <a>: the href
    anchor_text: str | None = None  # for html-href: the display text


class _LinkExtractor(HTMLParser):
    """Structural HTML link/text collector. Never renders anything."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.attr_urls: list[tuple[str, str, str]] = []  # (value, tag, attr)
        self.text_nodes: list[tuple[str, str | None]] = []  # (text, anchor href)
        self._anchor_href: str | None = None
        self._anchor_text: list[str] = []
        self.anchor_pairs: list[tuple[str, str]] = []  # (href, display text)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        for name, value in attrs:
            if value is None:
                continue
            name = name.lower()
            if tag == "a" and name == "href":
                self.attr_urls.append((value, tag, name))
                self._anchor_href = value
                self._anchor_text = []
            elif name in ("src", "href"):
                self.attr_urls.append((value, tag, name))

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._anchor_href is not None:
            self.anchor_pairs.append(
                (self._anchor_href, "".join(self._anchor_text).strip())
            )
            self._anchor_href = None
            self._anchor_text = []

    def handle_data(self, data: str) -> None:
        if not data.strip():
            return
        self.text_nodes.append((data, self._anchor_href))
        if self._anchor_href is not None:
            self._anchor_text.append(data)


def _decode_text(
    part: Message, index: str, warnings: list[ParserWarning]
) -> str | None:
    """Decode a text part payload; None (with warning) on failure."""
    try:
        payload = part.get_payload(decode=True)
    except Exception as exc:
        warnings.append(
            ParserWarning(
                code="url-body-decode-failed",
                detail=f"could not decode part payload: {exc}",
                part=index,
            )
        )
        return None
    if payload is None:
        return ""
    if isinstance(payload, str):
        payload = payload.encode("utf-8", errors="replace")
    if not isinstance(payload, bytes):
        warnings.append(
            ParserWarning(
                code="url-body-decode-failed",
                detail="unexpected payload shape; skipping part",
                part=index,
            )
        )
        return ""
    if len(payload) > MAX_TEXT_BYTES_PER_PART:
        warnings.append(
            ParserWarning(
                code="url-text-truncated",
                detail=(
                    f"text part exceeds {MAX_TEXT_BYTES_PER_PART:,} decoded "
                    f"bytes; scanning the first "
                    f"{MAX_TEXT_BYTES_PER_PART:,} only"
                ),
                part=index,
            )
        )
        payload = payload[:MAX_TEXT_BYTES_PER_PART]
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, ValueError):
        return payload.decode("utf-8", errors="replace")


def _is_attachment(part: Message) -> bool:
    if part.get_content_disposition() == "attachment":
        return True
    return part.get_filename() is not None


def _scan_html(
    html: str,
    index: str,
    candidates: list[UrlCandidate],
    warnings: list[ParserWarning],
) -> None:
    extractor = _LinkExtractor()
    try:
        extractor.feed(html)
        extractor.close()
    except Exception as exc:  # HTMLParser is lenient; this is belt-and-braces
        warnings.append(
            ParserWarning(
                code="url-html-parse-failed",
                detail=f"HTML link extraction failed: {exc}",
                part=index,
            )
        )
        return
    anchor_text_by_href: dict[str, str] = {}
    for href, text in extractor.anchor_pairs:
        # Keep the first display text seen per href value.
        anchor_text_by_href.setdefault(href, text)
    for value, tag, attr in extractor.attr_urls:
        kind = "html-href" if attr == "href" else "html-src"
        for candidate, defanged in iter_url_candidates(value):
            candidates.append(
                UrlCandidate(
                    text=candidate,
                    kind=kind,
                    detail=f"{index} <{tag} {attr}>",
                    defanged_in_source=defanged,
                    anchor_text=anchor_text_by_href.get(value),
                )
            )
    for text, anchor_href in extractor.text_nodes:
        for candidate, defanged in iter_url_candidates(text):
            candidates.append(
                UrlCandidate(
                    text=candidate,
                    kind="html-text",
                    detail=index,
                    defanged_in_source=defanged,
                    anchor_href=anchor_href,
                )
            )


def _walk_parts(
    part: Message,
    index: str,
    candidates: list[UrlCandidate],
    warnings: list[ParserWarning],
    state: dict[str, int],
) -> None:
    if part.is_multipart():
        payload = part.get_payload()
        subparts = payload if isinstance(payload, list) else []
        for i, sub in enumerate(subparts):
            _walk_parts(sub, f"{index}.{i}", candidates, warnings, state)
        return
    if _is_attachment(part):
        return  # attachment filenames are never URLs
    content_type = part.get_content_type()
    if content_type not in ("text/plain", "text/html"):
        return
    if state["text_parts"] >= MAX_TEXT_PARTS:
        if not state.get("parts_warned"):
            warnings.append(
                ParserWarning(
                    code="url-too-many-text-parts",
                    detail=(
                        f"more than {MAX_TEXT_PARTS} text parts; "
                        "scanning the first ones only"
                    ),
                )
            )
            state["parts_warned"] = 1
        return
    state["text_parts"] += 1
    text = _decode_text(part, index, warnings)
    if text is None:
        return
    if content_type == "text/html":
        _scan_html(text, index, candidates, warnings)
    else:
        for candidate, defanged in iter_url_candidates(text):
            candidates.append(
                UrlCandidate(
                    text=candidate,
                    kind="body-text",
                    detail=index,
                    defanged_in_source=defanged,
                )
            )


def _scan_headers(
    msg: Message,
    candidates: list[UrlCandidate],
    warnings: list[ParserWarning],
) -> None:
    items: list[tuple[str, str]]
    try:
        items = [(str(n), str(v)) for n, v in msg.raw_items()]
    except Exception:
        items = [(str(n), str(v)) for n, v in msg.items()]
    for name, value in items:
        for candidate, defanged in iter_url_candidates(value):
            candidates.append(
                UrlCandidate(
                    text=candidate,
                    kind="header",
                    detail=name,
                    defanged_in_source=defanged,
                )
            )


def extract_candidates(raw: bytes, warnings: list[ParserWarning]) -> list[UrlCandidate]:
    """Extract URL candidates from raw message bytes (read-only).

    Returns candidates in document order: body parts first (MIME
    order), then headers. Caps the total at
    :data:`MAX_URL_CANDIDATES` with a warning.
    """
    try:
        msg = email.message_from_bytes(raw)
    except Exception as exc:
        warnings.append(
            ParserWarning(
                code="url-parse-failed",
                detail=f"message re-parse for URL extraction failed: {exc}",
            )
        )
        return []
    candidates: list[UrlCandidate] = []
    _walk_parts(msg, "0", candidates, warnings, {"text_parts": 0})
    _scan_headers(msg, candidates, warnings)
    if len(candidates) > MAX_URL_CANDIDATES:
        warnings.append(
            ParserWarning(
                code="url-candidate-cap",
                detail=(
                    f"{len(candidates):,} URL candidates found; keeping the "
                    f"first {MAX_URL_CANDIDATES:,}"
                ),
            )
        )
        candidates = candidates[:MAX_URL_CANDIDATES]
    return candidates
