# Changelog

All notable changes to PhishScope are documented here. The format follows
"Keep a Changelog" conventions; versioning tracks the master plan.

## [Unreleased]

## [0.4.0] — 2026-10-03

URL/domain extraction & triage, fully offline (plan Phase 4).

### Added
- New `phishscope.urls` package (stdlib only): `models`
  (UrlRecord / UrlSource / UrlObservation / UrlAnalysis), `defang`
  (defang/undefang, defanged-source recognition, URL candidate
  regex), `decompose` (local URL decomposition: scheme/host/port/
  path/query/fragment, IDNA display forms, IP-literal detection,
  naive last-two-labels registered domain, shortener list, dedup
  keys), `extract` (read-only candidate extraction from raw bytes:
  text parts, structural HTML parsing via `html.parser`, all header
  values; attachment parts skipped), `observations`
  (observation-only forensics), `analysis` (whole-message URL
  analysis).
- Observation-only URL forensics (facts with basis, never verdicts):
  `display-href-mismatch`, `ip-literal-host`, `punycode-host`,
  `shortened-url` (target never expanded — offline), `nonstandard-
  port`, `http-scheme`, `userinfo-present`, `many-query-params`,
  `deep-subdomain`, `defanged-in-source`, `url-count`/`no-urls`.
  Query parameter values are evidence — kept verbatim, never
  redacted.
- Deduplication with per-URL provenance: repeated sightings merge
  into one record naming each source (body part, HTML attribute,
  header) with repeat counts; defanged spellings in the source
  (`hxxp`, `[.]`, `[:]`) are recognized and normalized to the exact
  URL for the canonical record.
- Offline boundary: URLs are never fetched, hostnames are never
  resolved, shorteners are never expanded; HTML is parsed
  structurally and never rendered. Verified by dedicated no-network
  tests that block all sockets.
- CLI: `phishscope urls <file.eml> [--json]` (focused inventory with
  the offline boundary stated up front; human output always
  defanged, `--json` carries exact values); `analyze --urls` appends
  a URL section and merges a `urls` block (provenance
  `phishscope.urls` v0.4.0) into `--json`; plugin registry gains the
  `urls` module (v0.4.0).
- Fixtures: URL variety (IP literal, punycode, display/href
  mismatch, shortener, tracking params, deep subdomains, header
  URLs, repeated URLs), defanged-source, malformed URLs,
  URL-free message; docs example `docs/examples/invoice-scam-urls.eml`
  (BEC lure with the classic mismatch shape) and terminal screenshot
  `docs/images/04-urls.png`.
- Extraction caps (documented): 50 text parts, 1 MB decoded text per
  part, 2,000 URL candidates — caps record warnings, never crashes.

## [0.3.0] — 2026-10-03

SPF/DKIM/DMARC authentication analysis, fully offline (plan Phase 3).

### Added
- New `phishscope.auth` package (stdlib only): `authentication_results`
  (RFC 8601-tolerant Authentication-Results parser: authserv-id,
  per-method result tokens, reasons, `smtp.mailfrom` / `header.i` /
  `header.from` properties; multiple headers kept separately),
  `dkim` (DKIM-Signature tag extraction: d=/s=/a=/c=/h=/bh= recorded
  verbatim), `received_spf` (Received-SPF result + detail), `analysis`
  (whole-message auth analysis), `models` (AuthMethodResult /
  DkimSignature / ReceivedSpf / AuthObservation / AuthAnalysis).
- Observation-only auth forensics (facts with basis, never verdicts):
  per-method result observations, DKIM-signature-present/absent,
  conflicting Authentication-Results across hops, Received-SPF vs
  Authentication-Results disagreements, DMARC-style alignment in
  strict (exact match) and relaxed (naive last-two-labels
  organizational domain, no PSL — documented approximation) modes.
- Offline boundary: no DNS lookups of any kind (no SPF record
  fetching, no DKIM key retrieval, no DMARC policy fetching); DKIM
  signatures parsed but never cryptographically verified; every
  result framed as a header claim ("metadata claims are not proof").
- CLI: `phishscope auth <file.eml> [--json]` (focused authentication
  view with the offline boundary stated up front); `analyze --headers`
  appends an authentication section and merges an `authentication`
  block (provenance `phishscope.auth` v0.3.0) into `--json`; plugin
  registry gains the `auth` module (v0.3.0).
- Fixtures: all-pass / spf-fail / dkim-none / conflicting /
  misaligned / malformed auth headers; docs example
  `docs/examples/invoice-scam-auth.eml` (BEC lure: spf pass, dkim
  none, dmarc fail).

## [0.2.0] — 2026-10-03

Header & Received-chain forensics (plan Phase 2).

### Added
- New `phishscope.headers` package (stdlib only): `received` (tolerant
  Received-header parser, hops ordered oldest-to-newest), `analysis`
  (whole-message header analysis), `models` (ReceivedHop /
  HeaderObservation / HeaderAnalysis).
- Received parsing: from/by host + IP (IPv4/IPv6 bracketed literals
  validated locally with `ipaddress`), protocol, queue ID, timestamp
  with verbatim original and UTC normalization (timezones never
  invented); verbatim header value always kept on the hop; malformed
  lines become recorded warnings, never crashes.
- Observation-only chain forensics (facts with basis, never verdicts):
  hop counts, timestamp inversions, private/internal IP hops
  (RFC 1918/loopback/link-local/ULA/CGNAT — documentation ranges not
  flagged), missing timestamps, unverifiable from-claims, originating-IP
  claims. Metadata claims are not proof: hostnames never resolved.
- Routing/auth-relevant header normalization: Return-Path, Message-ID,
  Date, X-Originating-IP / X-Sender-IP, X-Mailer, User-Agent, List-*
  headers, MIME-Version, top-level Content-Type.
- CLI: `phishscope hops <file.eml> [--json]` (focused Received-chain
  view); `phishscope analyze --headers` (routing-headers section in
  human output, `headers` block merged into `--json`); plugin registry
  gains the `headers` module (v0.2.0).
- Fixtures: `docs/examples/invoice-scam.eml` gains a realistic 3-hop
  Received chain (BEC scenario); synthetic direct/mailing-list/
  inversion/private-IP/IPv6/minimal/malformed chains in tests.
- Docs: README v0.2 section, USAGE.md Received-chain scenario with a
  real terminal screenshot (`docs/images/02-hops.png`).

### Limitations
- No verdicts: observations only, analysts judge (heuristics: v0.6).
- No DNS/PTR checks, no URL extraction (v0.4), no SPF/DKIM/DMARC (v0.3),
  no attachment content inspection (v0.5).

## [0.1.0] — 2026-10-02

First release: safe message parsing foundation.

### Added
- Safe `.eml` / RFC 5322 parser (`phishscope.parsers.safe_eml`, stdlib
  `email` only): never renders HTML, never fetches remote content, never
  executes attachments; attachment payloads are hashed and discarded.
- Raw preservation: SHA-256 over the original bytes computed before
  parsing; `analyze --show-raw` prints verbatim bytes behind a safety
  banner; the normalized model carries the digest, never the content.
- Normalized message model: evidence ID (`PS-MSG-…`), UTC-normalized
  Date with verbatim original (timezones never invented), parsed
  From/To/Cc/Reply-To/Return-Path, Message-ID, Subject, MIME structure
  tree, attachment inventory (filename, MIME claim, size, SHA-256),
  parser warnings, provenance.
- Safety bounds: 25 MB message cap, 200 MIME parts, 1 MB header block,
  16 multipart nesting levels — violations rejected with exit code 2.
- CLI: `analyze [--json] [--show-raw]`, `overview [--json]`,
  `--version`; exit codes 0 ok / 1 warnings / 2 error; defanged URL
  display; deterministic JSON; audit logging; plugin registry (`core`
  v0.1.0).
- Docs: README, USAGE.md scenario walkthrough with a real screenshot,
  synthetic `docs/examples/invoice-scam.eml`, SECURITY.md,
  CONTRIBUTING.md, MIT license.
- CI: pytest + coverage gate (≥80%), ruff, mypy on Python 3.10–3.13,
  plus a Windows smoke job.

### Limitations
- No URL extraction (v0.4), no SPF/DKIM/DMARC (v0.3), no header/Received
  forensics (v0.2), no attachment content inspection (v0.5).
- No verdicts: the tool records observations; analysts judge.
