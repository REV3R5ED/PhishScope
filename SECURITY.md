# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a vulnerability

PhishScope processes potentially hostile email messages, so parser safety
is a first-class concern. If you find a security issue, please report it
privately rather than opening a public issue:

- Email the author directly (see GitHub profile REV3R5ED) with a
  description, reproduction steps, and the version affected.
- Allow a reasonable time for a fix before any public disclosure.

## Security-relevant design (v0.1)

- **Read-only evidence handling**: source files are only opened for
  reading; PhishScope never writes to the analyzed message.
- **Hash before analysis**: SHA-256 is computed before any parsing.
- **Untrusted input**: MIME structure is walked with hard bounds — 25 MB
  message cap, 200 MIME parts, 1 MB header cap, 16 levels of multipart
  nesting. Oversize or over-deep input is rejected with a clean error,
  never an uncaught exception.
- **Nothing executes**: PhishScope never renders HTML, never fetches
  remote content, never decodes attachment content beyond hashing.
  Attachments are inventoried (name, claimed type, size, SHA-256), not
  extracted.
- **Raw preservation**: the original bytes are kept verbatim and are
  only shown via `--show-raw` behind an explicit safety banner.
- **Defanged display**: URLs in human-readable output are defanged
  (`hxxp://…[.]`) so they cannot be followed by accident. Machine
  output (`--json`) carries exact values for tooling.
- **No subprocess, no shell**: v0.1 performs no subprocess calls at all.
- **No network access**: nothing in PhishScope opens a network
  connection (covered by a dedicated test).
- **Stdlib-only**: zero third-party dependencies, no supply-chain surface.
- **Audit trail**: every CLI invocation appends a JSON record to the
  local audit log (best effort; logging never breaks a run).
