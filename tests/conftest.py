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
