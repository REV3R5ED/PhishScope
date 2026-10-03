"""Synthetic .eml fixtures for PhishScope tests.

Every fixture is built in-process with the stdlib ``email`` package or
hand-crafted byte strings — no real mailboxes, no network, fully
deterministic.
"""

from __future__ import annotations

import email.utils
from email.message import EmailMessage
from pathlib import Path


def write_eml(tmp_path: Path, data: bytes, name: str = "message.eml") -> str:
    """Write raw message bytes to a temp file; return its path."""
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def simple_text() -> bytes:
    """Minimal well-formed single-part message."""
    msg = EmailMessage()
    msg["From"] = "Alice Example <alice@example.com>"
    msg["To"] = "bob@example.com"
    msg["Subject"] = "Hello"
    msg["Date"] = "Fri, 02 Oct 2026 12:00:00 +0000"
    msg["Message-ID"] = "<simple-001@example.com>"
    msg.set_content("Hi Bob,\n\nSee you soon.\n")
    return msg.as_bytes()


def multipart_mixed_with_attachment() -> bytes:
    """multipart/mixed with a text part, an HTML part, and an attachment."""
    msg = EmailMessage()
    msg["From"] = "Acme Corp Billing <billing@acme-invoices.net>"
    msg["To"] = "victim@northwind.example"
    msg["Reply-To"] = "accounts@acme-billing-support.com"
    msg["Subject"] = "URGENT: Past-due invoice #INV-4821"
    msg["Date"] = "Fri, 02 Oct 2026 14:30:00 +0000"
    msg["Message-ID"] = "<inv-4821@acme-invoices.net>"
    msg.make_mixed()
    text = EmailMessage()
    text.set_content("Please remit payment immediately.\n")
    html = EmailMessage()
    html.set_content(
        "<html><body>Please remit payment immediately.</body></html>", subtype="html"
    )
    attach = EmailMessage()
    attach.set_content(
        b"%PDF-1.4 fake-invoice-bytes",
        maintype="application",
        subtype="octet-stream",
        disposition="attachment",
        filename="Invoice_INV-4821.pdf",
    )
    for part in (text, html, attach):
        msg.attach(part)
    return msg.as_bytes()


def multipart_alternative() -> bytes:
    """multipart/alternative with text + HTML bodies."""
    msg = EmailMessage()
    msg["From"] = "news@example.org"
    msg["To"] = "reader@example.com"
    msg["Subject"] = "Weekly digest"
    msg["Date"] = "Thu, 01 Oct 2026 09:00:00 +0000"
    msg["Message-ID"] = "<digest-99@example.org>"
    msg.set_content("Plain text digest.\n")
    msg.add_alternative("<html><body>Plain text digest.</body></html>", subtype="html")
    return msg.as_bytes()


def encoded_subject_and_address() -> bytes:
    """RFC 2047 encoded subject and non-ASCII display name."""
    msg = EmailMessage()
    msg["From"] = "Renée Dupont <renee@example.fr>"
    msg["To"] = "bob@example.com"
    msg["Subject"] = "Facture impayée — action requise"
    msg["Date"] = "Fri, 02 Oct 2026 08:15:00 +0200"
    msg["Message-ID"] = "<encoded-007@example.fr>"
    msg.set_content("Bonjour,\n\nVeuillez régler votre facture.\n")
    return msg.as_bytes()


def missing_date() -> bytes:
    """Well-formed except the Date header is absent."""
    msg = EmailMessage()
    msg["From"] = "alice@example.com"
    msg["To"] = "bob@example.com"
    msg["Subject"] = "No date here"
    msg["Message-ID"] = "<nodate-1@example.com>"
    msg.set_content("No Date header.\n")
    return msg.as_bytes()


def malformed_mime() -> bytes:
    """Hand-crafted message with MIME defects (bad boundary usage)."""
    return (
        b"From: alice@example.com\r\n"
        b"To: bob@example.com\r\n"
        b"Subject: =?utf-8?q?broken?=\r\n"
        b"Date: Fri, 02 Oct 2026 12:00:00 +0000\r\n"
        b"Message-ID: <malformed-1@example.com>\r\n"
        b"Content-Type: multipart/mixed; boundary=REALBOUNDARY\r\n"
        b"\r\n"
        b"--WRONGBOUNDARY\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"this part never parses as MIME\r\n"
        b"--REALBOUNDARY--\r\n"
    )


def truncated_message() -> bytes:
    """A valid multipart message cut off mid-stream."""
    full = multipart_mixed_with_attachment()
    return full[: len(full) * 3 // 5]


def deep_nesting(depth: int) -> bytes:
    """multipart/mixed nested ``depth`` levels deep."""
    inner: EmailMessage = EmailMessage()
    inner.set_content("leaf\n")
    current: EmailMessage = inner
    for _ in range(depth):
        outer = EmailMessage()
        outer.make_mixed()
        outer.attach(current)
        current = outer
    current["From"] = "alice@example.com"
    current["To"] = "bob@example.com"
    current["Subject"] = "deep"
    current["Date"] = "Fri, 02 Oct 2026 12:00:00 +0000"
    current["Message-ID"] = "<deep-1@example.com>"
    return current.as_bytes()


def many_parts(count: int) -> bytes:
    """multipart/mixed with ``count`` text sub-parts."""
    msg = EmailMessage()
    msg["From"] = "alice@example.com"
    msg["To"] = "bob@example.com"
    msg["Subject"] = "many parts"
    msg["Date"] = "Fri, 02 Oct 2026 12:00:00 +0000"
    msg["Message-ID"] = "<many-1@example.com>"
    msg.make_mixed()
    for i in range(count):
        part = EmailMessage()
        part.set_content(f"part {i}\n")
        msg.attach(part)
    return msg.as_bytes()


def huge_header() -> bytes:
    """Message whose header block exceeds 1 MB."""
    msg = EmailMessage()
    msg["From"] = "alice@example.com"
    msg["To"] = "bob@example.com"
    msg["Subject"] = "big header"
    msg["Date"] = "Fri, 02 Oct 2026 12:00:00 +0000"
    msg["Message-ID"] = "<bighdr-1@example.com>"
    msg["X-Padding"] = "x" * (1_200_000)
    msg.set_content("body\n")
    return msg.as_bytes()


def naive_date() -> bytes:
    """Date header without a timezone — UTC must NOT be invented."""
    return (
        b"From: alice@example.com\r\n"
        b"To: bob@example.com\r\n"
        b"Subject: naive\r\n"
        b"Date: Fri, 02 Oct 2026 12:00:00\r\n"
        b"Message-ID: <naive-1@example.com>\r\n"
        b"\r\n"
        b"body\r\n"
    )


def unparseable_date() -> bytes:
    """Date header that cannot be parsed at all."""
    return (
        b"From: alice@example.com\r\n"
        b"To: bob@example.com\r\n"
        b"Subject: baddate\r\n"
        b"Date: not a date at all\r\n"
        b"Message-ID: <baddate-1@example.com>\r\n"
        b"\r\n"
        b"body\r\n"
    )


def url_in_subject() -> bytes:
    """Subject containing a URL (for defang tests)."""
    msg = EmailMessage()
    msg["From"] = "alice@example.com"
    msg["To"] = "bob@example.com"
    msg["Subject"] = "See http://evil.example.com/login for details"
    msg["Date"] = "Fri, 02 Oct 2026 12:00:00 +0000"
    msg["Message-ID"] = "<url-1@example.com>"
    msg.set_content("body\n")
    return msg.as_bytes()


def format_date_for_header() -> str:
    """Helper: RFC 5322 date string for 'now' (UTC)."""
    import datetime

    return email.utils.format_datetime(
        datetime.datetime.now(datetime.timezone.utc), usegmt=False
    )


# ---------------------------------------------------------------------------
# v0.2 header-forensics fixtures (hand-crafted byte strings)
# ---------------------------------------------------------------------------

_HDR_BASE = (
    b"From: sender@example.net\r\n"
    b"To: victim@example.com\r\n"
    b"Subject: headers test\r\n"
    b"Date: Fri, 02 Oct 2026 14:30:00 +0000\r\n"
    b"Message-ID: <hdr-test@example.net>\r\n"
    b"Return-Path: <bounce@example.net>\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
)


def _with_headers(extra: bytes) -> bytes:
    return extra + _HDR_BASE + b"\r\n" + b"body\r\n"


def direct_send_eml() -> bytes:
    """Clean two-hop chain, oldest first in time."""
    return _with_headers(
        b"Received: from mail.example.net (mail.example.net [192.0.2.10])\r\n"
        b"\tby mx.example.com with ESMTPS id AAA111;\r\n"
        b"\tFri, 02 Oct 2026 14:31:00 +0000\r\n"
        b"Received: from client.example.net ([192.0.2.25])\r\n"
        b"\tby mail.example.net with ESMTP id BBB222;\r\n"
        b"\tFri, 02 Oct 2026 14:30:05 +0000\r\n"
    )


def mailing_list_eml() -> bytes:
    """Forwarded via a mailing list: List-* headers, three hops."""
    return _with_headers(
        b"Received: from mail.example.net (mail.example.net [192.0.2.10])\r\n"
        b"\tby mx.example.com with ESMTPS id CCC333;\r\n"
        b"\tFri, 02 Oct 2026 15:01:00 +0000\r\n"
        b"Received: from lists.example.org (lists.example.org [203.0.113.9])\r\n"
        b"\tby mail.example.net with ESMTP id DDD444;\r\n"
        b"\tFri, 02 Oct 2026 15:00:10 +0000\r\n"
        b"Received: from poster.example.org ([198.51.100.60])\r\n"
        b"\tby lists.example.org with ESMTP id EEE555;\r\n"
        b"\tFri, 02 Oct 2026 14:59:00 +0000\r\n"
        b"List-Id: <announce.example.org>\r\n"
        b"List-Unsubscribe: <mailto:leave@example.org>\r\n"
        b"X-Mailer: ListManager 9.1\r\n"
    )


def timestamp_inversion_eml() -> bytes:
    """Middle hop timestamp is newer than the final hop (clock skew)."""
    return _with_headers(
        b"Received: from mail.example.net (mail.example.net [192.0.2.10])\r\n"
        b"\tby mx.example.com with ESMTPS id FFF666;\r\n"
        b"\tFri, 02 Oct 2026 14:31:00 +0000\r\n"
        b"Received: from client.example.net ([192.0.2.25])\r\n"
        b"\tby mail.example.net with ESMTP id GGG777;\r\n"
        b"\tFri, 02 Oct 2026 14:35:00 +0000\r\n"
    )


def private_ip_hop_eml() -> bytes:
    """First hop originates from a private (RFC 1918) address."""
    return _with_headers(
        b"Received: from mail.example.net (mail.example.net [192.0.2.10])\r\n"
        b"\tby mx.example.com with ESMTPS id HHH888;\r\n"
        b"\tFri, 02 Oct 2026 14:31:00 +0000\r\n"
        b"Received: from internal-pc (internal-pc [192.168.1.10])\r\n"
        b"\tby mail.example.net with ESMTP id III999;\r\n"
        b"\tFri, 02 Oct 2026 14:30:05 +0000\r\n"
    )


def ipv6_hop_eml() -> bytes:
    """Bracketed IPv6 literals in from/by clauses."""
    return _with_headers(
        b"Received: from mail.example.net (mail.example.net [IPv6:2001:db8::10])\r\n"
        b"\tby mx.example.com ([IPv6:2001:db8::1]) with ESMTPS id JJJ000;\r\n"
        b"\tFri, 02 Oct 2026 14:31:00 +0000\r\n"
    )


def minimal_headers_eml() -> bytes:
    """No Received headers at all."""
    return _with_headers(b"")


def malformed_received_eml() -> bytes:
    """Garbage Received lines: must not crash, warnings recorded."""
    return _with_headers(
        b"Received: this is not a received header at all\r\n"
        b"Received:\r\n"
        b"Received: from [not-an-ip!!!] by; some; junk;\r\n"
    )


def x_originating_ip_eml() -> bytes:
    """Webmail-style originating IP headers."""
    return _with_headers(
        b"Received: from webmail.example.net (webmail.example.net [192.0.2.10])\r\n"
        b"\tby mx.example.com with ESMTPS id KKK111;\r\n"
        b"\tFri, 02 Oct 2026 14:31:00 +0000\r\n"
        b"X-Originating-IP: [203.0.113.200]\r\n"
        b"X-Mailer: WebMail 3.0\r\n"
        b"User-Agent: WebMail/3.0\r\n"
    )


# ---------------------------------------------------------------------------
# v0.3 authentication fixtures (hand-crafted byte strings)
# ---------------------------------------------------------------------------

_AUTH_AR_ALL_PASS = (
    b"Authentication-Results: mx.northwind.example;\r\n"
    b"\tspf=pass (sender IP is 203.0.113.45) "
    b"smtp.mailfrom=bounce-9917@acme-invoices.net;\r\n"
    b"\tdkim=pass (signature was verified) "
    b"header.i=@acme-invoices.net header.s=sel2026;\r\n"
    b"\tdmarc=pass (p=reject) header.from=acme-invoices.net\r\n"
)

_AUTH_DKIM_SIG = (
    b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=acme-invoices.net;\r\n"
    b"\ts=sel2026; t=1727874600;\r\n"
    b"\tbh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;\r\n"
    b"\th=From:To:Subject:Date:Message-ID;\r\n"
    b"\tb=ZnJpZW5kc2lnbmF0dXJlY2xhaW1ub3R2ZXJpZmllZA==\r\n"
)

_AUTH_RSPF_PASS = (
    b"Received-SPF: pass (mx.northwind.example: domain of "
    b"bounce-9917@acme-invoices.net designates 203.0.113.45 as permitted "
    b"sender) client-ip=203.0.113.45;\r\n"
)


def auth_all_pass_eml() -> bytes:
    """SPF+DKIM+DMARC all pass; DKIM-Signature present; aligned."""
    return _with_headers(_AUTH_AR_ALL_PASS + _AUTH_DKIM_SIG + _AUTH_RSPF_PASS)


def auth_spf_fail_eml() -> bytes:
    """SPF hard-fails; DKIM absent; DMARC fails."""
    return _with_headers(
        b"Authentication-Results: mx.northwind.example;\r\n"
        b"\tspf=fail (sender IP is 198.51.100.77) "
        b"smtp.mailfrom=bounce-9917@acme-invoices.net;\r\n"
        b"\tdkim=none (no signature) header.d=none;\r\n"
        b"\tdmarc=fail (p=reject) header.from=acme-invoices.net\r\n"
        b"Received-SPF: fail (mx.northwind.example: 198.51.100.77 is not "
        b"a permitted sender) client-ip=198.51.100.77;\r\n"
    )


def auth_dkim_none_eml() -> bytes:
    """SPF passes but no DKIM signature at all (the BEC-lure shape)."""
    return _with_headers(
        b"Authentication-Results: mx.northwind.example;\r\n"
        b"\tspf=pass (sender IP is 203.0.113.45) "
        b"smtp.mailfrom=bounce-9917@acme-invoices.net;\r\n"
        b"\tdkim=none (no signature) header.d=none;\r\n"
        b"\tdmarc=none (no policy) header.from=acme-invoices.net\r\n"
        b"Received-SPF: pass (mx.northwind.example: domain of "
        b"bounce-9917@acme-invoices.net designates 203.0.113.45 as permitted "
        b"sender) client-ip=203.0.113.45;\r\n"
    )


def auth_conflicting_eml() -> bytes:
    """Two Authentication-Results headers disagree on SPF."""
    return _with_headers(
        b"Authentication-Results: mx.northwind.example;\r\n"
        b"\tspf=pass (sender IP is 203.0.113.45) "
        b"smtp.mailfrom=bounce-9917@acme-invoices.net\r\n"
        b"Authentication-Results: gateway.example.org;\r\n"
        b"\tspf=fail (forged sender) smtp.mailfrom=bounce-9917@acme-invoices.net\r\n"
    )


def auth_misaligned_eml() -> bytes:
    """SPF passes for a different domain than From (unaligned)."""
    return _with_headers(
        b"Authentication-Results: mx.northwind.example;\r\n"
        b"\tspf=pass (sender IP is 198.51.100.99) "
        b"smtp.mailfrom=bounce@evil-relay.example;\r\n"
        b"\tdkim=none header.d=none;\r\n"
        b"\tdmarc=fail header.from=acme-invoices.net\r\n"
    )


def auth_malformed_eml() -> bytes:
    """Garbage auth headers: must not crash, warnings recorded."""
    return _with_headers(
        b"Authentication-Results: just some words no semicolons\r\n"
        b"Authentication-Results: mx.example.com; spf; dkim==weird\r\n"
        b"DKIM-Signature: not-a-tag-list\r\n"
        b"DKIM-Signature: \r\n"
        b"Received-SPF: \r\n"
        b"Received-SPF: (no result token here)\r\n"
    )


# ---------------------------------------------------------------------------
# v0.4 URL/domain fixtures (hand-crafted byte strings)
# ---------------------------------------------------------------------------

_URLS_HTML = (
    b"<html><body>\r\n"
    b"<p>Dear customer, verify your account:</p>\r\n"
    # display text is a URL that differs from the href target
    b'<p><a href="https://secure-login.example.net/verify?id=9917">'
    b"https://www.acme-invoices.net/verify</a></p>\r\n"
    # shortener link with plain-text anchor
    b'<p><a href="https://bit.ly/3xYzAb12">track your shipment</a></p>\r\n'
    # tracking pixel on an IP literal with a non-standard port
    b'<img src="http://192.0.2.44:8080/p.gif">\r\n'
    b"</body></html>\r\n"
)

_URLS_TEXT = (
    b"Dear customer,\r\n"
    b"\r\n"
    b"Your invoice is ready: https://billing.acme-invoices.net/inv/4821\r\n"
    b"Mirror (IP literal): http://192.0.2.44/inv/4821\r\n"
    b"Punycode portal: https://xn--pple-43d.example/verify\r\n"
    b"Tracking: https://track.example.org/click?utm_source=mail&utm_medium=email"
    b"&utm_campaign=inv&sid=9917&ts=1727874600&sig=abcdef123456\r\n"
    b"Deep chain: https://a.b.c.d.example.com/deep/path\r\n"
    b"Also see https://billing.acme-invoices.net/inv/4821 (repeated).\r\n"
)


def urls_variety_eml() -> bytes:
    """URL variety: IP literal, punycode, mismatch, shortener, tracking,
    deep subdomains, header URLs, repeated URLs, and an attachment whose
    filename must never be treated as a URL."""
    return (
        b"From: Acme Corp Billing <billing@acme-invoices.net>\r\n"
        b"To: victim@northwind.example\r\n"
        b"Subject: Your invoice #INV-4821\r\n"
        b"Date: Fri, 02 Oct 2026 14:30:00 +0000\r\n"
        b"Message-ID: <urls-variety@example.net>\r\n"
        b"List-Unsubscribe: <https://lists.acme-invoices.net/unsub?user=9917>\r\n"
        b"Content-Type: multipart/mixed; boundary=URLSBOUNDARY\r\n"
        b"\r\n"
        b"--URLSBOUNDARY\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n" + _URLS_TEXT + b"\r\n"
        b"--URLSBOUNDARY\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"\r\n" + _URLS_HTML + b"\r\n"
        b"--URLSBOUNDARY\r\n"
        b"Content-Type: application/pdf\r\n"
        b'Content-Disposition: attachment; filename="http-invoice.pdf"\r\n'
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        b"JVBERi0xLjQK\r\n"
        b"--URLSBOUNDARY--\r\n"
    )


def urls_defanged_eml() -> bytes:
    """Body already contains defanged URLs (threat-report style)."""
    return (
        b"From: soc@example.org\r\n"
        b"To: analyst@example.com\r\n"
        b"Subject: IOCs from incident 42\r\n"
        b"Date: Fri, 02 Oct 2026 15:00:00 +0000\r\n"
        b"Message-ID: <urls-defanged@example.org>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Observed indicators:\r\n"
        b"hxxps://evil[.]example/login\r\n"
        b"hxxp://bad[.]example:8080/x\r\n"
        b"http[:]//weird[.]example/path\r\n"
    )


def urls_malformed_eml() -> bytes:
    """Malformed URL shapes: must not crash, warnings recorded."""
    return (
        b"From: alice@example.com\r\n"
        b"To: bob@example.com\r\n"
        b"Subject: malformed urls\r\n"
        b"Date: Fri, 02 Oct 2026 12:00:00 +0000\r\n"
        b"Message-ID: <urls-malformed@example.com>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"bare scheme: http:// and that's it\r\n"
        b"bad bracket: https://[bad\r\n"
        b"bad port: http://example.com:abc/path\r\n"
        b"not a url: just some words\r\n"
        b"huge: https://example.com/" + b"a" * 3000 + b"\r\n"
    )


def urls_none_eml() -> bytes:
    """A clean message with no URLs at all."""
    return _with_headers(b"")
