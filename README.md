# PhishScope

**Trace the message. Expose the evidence.**

PhishScope is a Python email and phishing forensics platform. It starts as a safe message parser — raw `.eml`/RFC 5322 parsing with zero execution, cryptographic hashes, raw-byte preservation, and a normalized message model — and grows into a full investigation platform: header forensics, SPF/DKIM/DMARC, URL triage, attachment forensics, impersonation heuristics, threat-intel correlation, case management, and defensible reporting.

The core forensic rules: **the original bytes are never modified and never embedded in analysis output; normalized fields are derived alongside them, never merged.** PhishScope records what a message *technically contains* and never labels a message "phishing" from a heuristic alone — humans make the final judgment.

## License

MIT — see [LICENSE](LICENSE). Free for personal and commercial use.

## v0.1 — what works today

- **Safe .eml/MIME parser** (`phishscope analyze message.eml`): stdlib `email` package only. Never renders HTML, never fetches remote content, never executes attachments. Attachment content is hashed and discarded — the model keeps filename, claimed MIME type, size, and SHA-256 only
- **Raw preservation**: SHA-256 computed over the original bytes *before* parsing; `analyze --show-raw` prints the verbatim bytes behind an explicit safety banner. The normalized model carries the digest, never the content — mutating analysis output cannot touch evidence
- **Normalized message model**: evidence ID (`PS-MSG-…`), UTC-normalized Date (original string kept verbatim; a timezone is never invented), parsed From/To/Cc/Reply-To/Return-Path (display name + addr), Message-ID, Subject, full MIME structure tree (content types, sizes, filenames — no content decoding), attachment inventory, parser warnings (MIME defects, encoding issues, truncation, missing headers), and provenance (parser name/version, analyzed-at UTC)
- **Safety bounds**: 25 MB message cap, 200 MIME parts, 1 MB header block, 16 levels of multipart nesting — violations are rejected with a clean error (exit 2), never a crash. Malformed input becomes recorded warnings (exit 1), never an exception
- **Defanged display**: URLs in human-readable output are defanged (`hxxp://…[.]`) so they can't be followed by accident; `--json` carries exact values for tooling; long header values are truncated for display (full values in `--json`)
- **CLI**: `phishscope analyze <message.eml> [--json] [--show-raw]`, `phishscope overview <message.eml> [--json]`, `phishscope --version`; structured exit codes (0 ok / 1 warnings / 2 error); deterministic JSON output; audit logging of every invocation; plugin registry with the `core` module (v0.1.0)

See [docs/USAGE.md](docs/USAGE.md) for a scenario walkthrough.

## Roadmap

- [x] **v0.1** — Safe .eml/MIME parser, hashes, raw preservation, normalized message model
- [ ] **v0.2** — Header & Received-chain forensics (ordered Received chain, display-name/address mismatches, IPv4/IPv6/domain indicators)
- [ ] **v0.3** — SPF/DKIM/DMARC analysis (Authentication-Results parsing, pass/fail/none + authenticating domain)
- [ ] **v0.4** — URL/domain extraction & triage (visible URLs, href targets, defanged indicators, display-vs-destination mismatch; no auto-visiting)
- [ ] **v0.5** — Attachment forensics (magic-byte type, extension/type mismatch, double extensions, risky types, archive inventory with strict limits; never execute)
- [ ] **v0.6** — Content & impersonation heuristics (urgency/credential/payment language, brand/domain mismatch; findings carry evidence + limitations)
- [ ] **v0.7** — Threat-intel adapters (optional, cached, timeouts), indicator correlation, STIX/JSON export; observed vs enriched distinguished
- [ ] **v0.8** — Case management (evidence registration, chain-of-custody audit, deterministic manifests, sanitized reports)
- [ ] **v0.9** — Batch/mailbox ingest, campaign clustering, local analyst UI, plugin boundary for mailbox connectors
- [ ] **v1.0** — Stable schemas, hardened parser limits, benchmark corpus, plugin API

## Safety model

PhishScope treats every message as hostile input:

- **Nothing executes.** No HTML rendering, no remote fetches, no attachment extraction beyond hashing. This is non-negotiable in every phase.
- **Read-only evidence.** Source files are only opened for reading; analysis never writes to them.
- **Bounded parsing.** Every structural walk has a hard cap; oversize input is rejected, not processed.
- **No network.** Verified by a dedicated test that blocks all sockets.
- **Stdlib-only.** Zero dependencies — no supply-chain surface.
- **Observed vs inferred.** The tool records claims found in the message; it never makes authenticity or phishing verdicts.

See [SECURITY.md](SECURITY.md) for the full policy.

## Limitations (v0.1)

- URL extraction, authentication analysis, header forensics, and attachment content inspection are later phases — v0.1 inventories structure only.
- The parser is lenient by design (warnings, not rejections) for malformed input; only safety-bound violations are hard errors.
- `Return-Path` / `Received` / `Authentication-Results` headers are preserved in raw bytes but not yet analyzed.

## Install

Requires Python 3.10+. Zero dependencies.

```bash
git clone https://github.com/REV3R5ED/PhishScope.git
cd PhishScope
pip install -e .
```

## Quickstart

```bash
phishscope overview suspicious.eml
phishscope analyze suspicious.eml --json > analysis.json
phishscope analyze suspicious.eml --show-raw   # original bytes, safety banner
```

## Project layout

```
src/phishscope/
├── core/      # config, models, hashing, logging, results, plugins
├── parsers/   # safe_eml.py (v0.1); header/auth/url/attachment parsers per roadmap
├── cli/       # argument parsing, rendering
└── ...        # headers/auth/urls/attachments/detection/intel/cases arrive per roadmap
tests/         # synthetic .eml fixtures, no network
docs/          # USAGE.md, examples/, images/
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
