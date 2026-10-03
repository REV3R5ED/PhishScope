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
PhishScope v0.2.0 — message analysis

Evidence ID : PS-MSG-14ECA2110DD4
Source      : docs/examples/invoice-scam.eml
SHA-256     : 14eca2110dd47c38…
Size        : 1,880 bytes
Date        : 2026-10-02T14:30:00+00:00  (original: Fri, 02 Oct 2026 14:30:00 +0000)
From        : Acme Corp Billing <billing@acme-invoices.net>
To          : Pouya Karim <pouya@northwind.example>
Reply-To    : accounts@acme-billing-support.com
Return-Path : <bounce-9917@acme-invoices.net>
Subject     : URGENT: Past-due invoice #INV-4821 — wire transfer required
Message-ID  : <inv-4821-urgent@acme-invoices.net>

MIME structure:
  [0] multipart/mixed (459 bytes)
    [0.0] text/plain (209 bytes)
    [0.1] text/html (192 bytes)
    [0.2] application/pdf — Invoice_INV-4821.pdf (58 bytes) [attachment]

Attachments (1):
  Invoice_INV-4821.pdf — application/pdf, 58 bytes, sha256:0f10d109…
  (content not extracted in v0.1 — hashes only)

Parser warnings: none
```

What you learn without opening the message:

- **Routing claims**: From, Reply-To, and Return-Path are three different
  domains. v0.2's header forensics (`phishscope hops`, `analyze
  --headers`) traces the Received chain hop by hop — but still never
  labels anything phishing; the normalized model hands you the parsed
  addresses to compare.
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

## Scenario: trace the Received chain (v0.2)

The invoice lure *claims* to come from Acme Corp Billing. Before
believing any header, trace how the message says it traveled. v0.2
parses every `Received` header into hops, oldest first, and reports
observation-only facts — never verdicts. Hostnames are never resolved
and nothing is fetched: a bracketed IP is an observed literal, a bare
hostname is an unverified claim.

```bash
phishscope hops docs/examples/invoice-scam.eml
```

![phishscope hops: Received chain of the invoice lure](images/02-hops.png)

Reading the chain oldest → newest:

- **Hop 0** — `billing-pc [10.0.0.23]` hands the message to `[10.0.0.23]`
  over SMTP. Both the from- and by-clause IPs are RFC 1918 private
  addresses: this hop happened on someone's internal network, not on
  the public internet. That's an observation, not an accusation — but
  it's the kind of fact that shapes the next question.
- **Hop 1** — `unknown [198.51.100.77]` relays to
  `mail.acme-invoices.net`. The from-hostname is literally "unknown":
  the relaying MTA is telling you it couldn't identify the sender.
- **Hop 2** — `mail.acme-invoices.net [203.0.113.45]` delivers to your
  `mx.northwind.example` over ESMTPS. This is the only hop whose
  from-claim matches the sender's domain.

Timestamps run 14:28:10 → 14:29:44 → 14:31:02 with no inversion, so the
clocks agree. Note what PhishScope does *not* say: it doesn't call the
message phishing, it doesn't resolve `mail.acme-invoices.net` to check
the claim, and it doesn't treat the private IP as proof of anything.

For the same data inside a full analysis, run `phishscope analyze
--headers <file>`: the `headers` block (routing headers, chain,
observations, header parser warnings, provenance) is appended to the
human output and merged into `--json`.

## Scenario: authenticate the invoice lure (v0.3)

The lure arrives with authentication headers this time
(`docs/examples/invoice-scam-auth.eml` — same message as the v0.2
scenario, plus the headers a receiving MTA would add). v0.3 parses
what those headers *claim* — fully offline. It never fetches an SPF
record, never retrieves a DKIM key, never verifies a signature:

```bash
phishscope auth docs/examples/invoice-scam-auth.eml
```

![phishscope auth: authentication claims of the invoice lure](images/03-auth.png)

Read it as claims, not facts:

- **`spf=pass`** — `mx.northwind.example` *claims* the sender IP was
  authorized for `acme-invoices.net`. SPF alignment is strict-aligned
  with the From domain. This is consistent with the v0.2 finding that
  the final hop really did come from `mail.acme-invoices.net` — but
  remember, anyone's infrastructure can write a passing SPF result for
  its own domain.
- **`dkim=none`** — no DKIM-Signature header exists at all. The
  message carries no cryptographic signer claim of its own.
- **`dmarc=fail`** — the claimed DMARC evaluation failed (policy
  `p=reject` in the reason). With SPF aligned but DKIM absent, this
  is the shape DMARC failure takes when a domain publishes a policy
  but the message carries no DKIM signature.
- Nothing here is a verdict. SPF passing for the envelope domain
  does not make the invoice legitimate, and DMARC failing does not
  make it phishing — forwarding and mailing lists break alignment
  routinely. The observations give you the claim geometry; you judge.

For the same data inside a full analysis, run `phishscope analyze
--headers <file>`: an `authentication` block (results, signatures,
observations, auth parser warnings, provenance `phishscope.auth`
v0.3.0) is appended to the human output and merged into `--json`.

## What v0.3 does NOT do (honest limits)

- **No verdicts.** Observations are facts with their basis attached;
  the analyst judges. Heuristics arrive in v0.6 with explicit
  limitations.
- **No DNS, no fetching, no verification.** SPF records are never
  fetched, DKIM keys are never retrieved, signatures are never
  cryptographically verified, hostnames are never resolved, URLs are
  never visited (v0.4). An `spf=pass` is only as trustworthy as the
  MTA that wrote the header.
- **No attachment content inspection** (v0.5).
- Relaxed alignment uses a naive last-two-labels organizational
  domain (no public-suffix list offline); strict exact-match
  alignment is always reported alongside.
- Displayed header values are truncated at 200 chars and URLs are
  defanged (`hxxp://…[.]`); `--json` always carries the full exact
  values.

## Scenario: inventory the lure's URLs (v0.4)

The invoice lure returns with links this time
(`docs/examples/invoice-scam-urls.eml` — same lure, plus a payment
portal, a "backup" portal, HTML buttons, and a List-Unsubscribe
header). v0.4 extracts every URL from body text, HTML link targets,
and headers, then decomposes each one locally — never fetched, never
resolved, shorteners never expanded:

```bash
phishscope urls docs/examples/invoice-scam-urls.eml
```

![phishscope urls: URL/domain inventory of the invoice lure](images/04-urls.png)

Read the inventory as observations, not verdicts:

- **`display-href-mismatch`** — the "Pay now" button's clickable text
  shows `portal.acme-invoices.net/pay/INV-4821` but the href target is
  `secure-pay.example.net/collect?inv=4821`. This is the classic
  phishing shape, and v0.4 still records it as an *observation*:
  heuristic judgments arrive in v0.6 with explicit limitations.
- **`ip-literal-host`** — the "backup portal" is `http://192.0.2.44/…`,
  a bare IPv4 address instead of a domain name, on plaintext `http`
  (`http-scheme`). Hostnames are easier to evaluate than bare
  addresses.
- **`shortened-url`** — `bit.ly/4kX9mQ2` is a known shortener; the
  target is *not* expanded because PhishScope is offline, so the true
  destination is recorded as unobserved.
- **Header URL** — `List-Unsubscribe` carries
  `portal.acme-invoices.net/unsub?user=9917`; query parameter values
  are evidence and are kept verbatim, never redacted.
- **Deduplication with provenance** — the payment portal appears in
  both the text body and the HTML visible text; it is one record with
  two sightings (each sighting counts its repeats).

For the same data inside a full analysis, run `phishscope analyze
--urls <file>`: a `urls` block (records, observations, URL parser
warnings, provenance `phishscope.urls` v0.4.0) is appended to the
human output and merged into `--json`. Human output is always
defanged; `--json` carries exact values for tooling.

## What v0.4 does NOT do (honest limits)

- **No verdicts.** Observations are facts with their basis attached;
  the analyst judges. Heuristics arrive in v0.6 with explicit
  limitations.
- **No fetching, no resolving, no expanding.** URLs are never
  visited, hostnames are never resolved (no DNS), and shortened URLs
  are never expanded — the target of a shortener is unobserved, not
  assumed benign or malicious.
- **No attachment content inspection** (v0.5) — attachment filenames
  are never treated as URLs.
- Registered-domain uses the naive last-two-labels approximation (no
  public-suffix list offline — `co.uk`-style suffixes are not
  handled); the exact host is always reported alongside.
- Only `http`/`https` URLs are extracted; bare domains without a
  scheme are not treated as URLs.
