# PhishScope Usage Guide

Scenario-driven walkthroughs. Every example uses the synthetic message in
`docs/examples/invoice-scam.eml` — a BEC-style invoice lure invented for
documentation (all senders, domains, and content are fictional).

## Scenario: a suspicious "past-due invoice"

You receive a forwarded message that smells wrong: urgent wire-transfer
language, an invoice attachment, a Reply-To that doesn't match the sender.
Before opening anything, you run it through PhishScope. PhishScope never
renders the HTML, never fetches anything, never touches the attachment
content — it inventories the message safely.

### Step 1 — Overview: what is this message?

```bash
phishscope overview docs/examples/invoice-scam.eml
```

![phishscope overview of the invoice lure](images/01-overview.png)

The overview gives you the evidence ID (`PS-MSG-…`, derived from the
raw-byte SHA-256), the UTC-normalized Date, parsed From/To, the subject,
the MIME structure (4 parts: text + HTML + attachment), and the
attachment inventory — in one screen. Note the From address is shown
exactly as claimed; v0.1 records claims, it does not judge them.

### Step 2 — Full analysis: the normalized message model

```bash
phishscope analyze docs/examples/invoice-scam.eml
```

```
PhishScope v0.1.0 — message analysis

Evidence ID : PS-MSG-D87007797851
Source      : docs/examples/invoice-scam.eml
SHA-256     : d870077978519d13…
Size        : 1,429 bytes
Date        : 2026-10-02T14:30:00+00:00  (original: Fri, 02 Oct 2026 14:30:00 +0000)
From        : Acme Corp Billing <billing@acme-invoices.net>
To          : Pouya Karim <pouya@northwind.example>
Reply-To    : accounts@acme-billing-support.com
Return-Path : <bounce-9917@acme-invoices.net>
Subject     : URGENT: Past-due invoice #INV-4821 — wire transfer required
Message-ID  : <inv-4821-urgent@acme-invoices.net>

MIME structure:
  [0] multipart/mixed (1,429 bytes)
    [0.0] text/plain (182 bytes)
    [0.1] text/html (203 bytes)
    [0.2] application/pdf — Invoice_INV-4821.pdf (57 bytes) [attachment]

Attachments (1):
  Invoice_INV-4821.pdf — application/pdf, 57 bytes, sha256:5a26…
  (content not extracted in v0.1 — hashes only)

Parser warnings: none
```

What you learn without opening the message:

- **Routing claims**: From, Reply-To, and Return-Path are three different
  domains. v0.1 doesn't flag this (that's v0.2's header forensics) — but
  the normalized model hands you the parsed addresses to compare.
- **The attachment**: name, claimed MIME type, size, and SHA-256. The
  *content* was hashed and discarded — PhishScope never extracted it.
  Pivot on the hash in your sandbox instead.
- **The HTML part exists** (203 bytes) and was never rendered. URL
  extraction is v0.4's job; nothing was fetched.

For automation, add `--json`: the full normalized model (evidence ID,
addresses, dates, MIME tree, attachments, warnings, provenance) with
exact, never-defanged values and deterministic key ordering.

### Step 3 — Raw preservation: prove what you analyzed

```bash
phishscope analyze docs/examples/invoice-scam.eml --show-raw
```

This prints a safety banner, then the **original bytes verbatim** — the
same bytes the SHA-256 was computed over. The normalized model never
contains raw content; the two are separate by construction, so mutating
analysis output can never alter evidence.

### Step 4 — Malformed input: warnings, not crashes

Feed PhishScope a truncated or mangled message and it records
`mime-defect` / `payload-decode-failed` / `missing-header` parser
warnings and exits 1 — the analysis still completes with whatever could
be recovered. Input that violates a safety bound (over 25 MB, over 200
MIME parts, header block over 1 MB, nesting deeper than 16) is rejected
with a clean error and exit code 2.

## What v0.1 does NOT do (honest limits)

- **No verdicts.** PhishScope never labels a message "phishing" —
  especially not from one heuristic. It records observations; the
  analyst judges.
- **No URL extraction** (v0.4), **no auth analysis** (v0.3), **no header
  forensics** (v0.2), **no attachment content inspection** (v0.5).
- **No network.** Nothing is fetched, ever — verified by a dedicated
  test that blocks all sockets.
- Displayed header values are truncated at 200 chars and URLs are
  defanged (`hxxp://…[.]`); `--json` always carries the full exact
  values.
