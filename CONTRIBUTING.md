# Contributing to PhishScope

## Ground rules

- **Stdlib-only.** PhishScope has zero dependencies by design (forensic
  tools minimize supply-chain surface). Do not add third-party packages
  without discussion.
- **Python 3.10–3.13.** No `tomllib`, no 3.11+-only constructs — CI runs
  the full matrix.
- **Raw vs normalized.** Original message bytes are kept verbatim;
  normalized fields are derived alongside them. Never merge the two,
  and never let the tool make phishing verdicts — record observations
  with evidence, nothing more.
- **Defensive parsing.** Email input is hostile. Bound everything,
  validate every structure, and turn malformed input into recorded
  warnings, not crashes.
- **Never execute message content.** No HTML rendering, no remote
  fetches, no attachment extraction beyond hashing. This is
  non-negotiable in every phase.

## Workflow

1. Fork and create a feature branch.
2. Add tests first for parser/behavior changes. Test fixtures are
   synthetic `.eml` messages built in `tests/conftest.py` — no real
   mailboxes, no network.
3. Run the gates locally before pushing:

```bash
pip install -e '.[dev]'
pytest -q
ruff check . && ruff format --check .
mypy src
```

4. Update `CHANGELOG.md` under `[Unreleased]`.
5. Open a PR with a clear description and sample output for CLI changes.

## Project layout

```
src/phishscope/
├── core/      # config, models, hashing, logging, results, plugins
├── parsers/   # safe_eml.py (v0.1); header/auth/url/attachment parsers land per roadmap
├── cli/       # argument parsing, rendering
└── ...        # headers/auth/urls/attachments/detection/intel/cases arrive per roadmap
tests/         # synthetic .eml fixtures, no network
```

Later roadmap phases plug into `core/plugins.py` and the models in
`core/models.py` — keep those seams stable.
