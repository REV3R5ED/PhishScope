# Changelog

All notable changes to PhishScope are documented here. The format follows
"Keep a Changelog" conventions; versioning tracks the master plan.

## [Unreleased]

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
