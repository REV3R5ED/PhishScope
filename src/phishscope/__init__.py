"""PhishScope — email and phishing forensics.

Trace the message. Expose the evidence.

v0.1: safe .eml/MIME parser (stdlib ``email`` only — nothing executes,
nothing renders, nothing fetches), SHA-256 hashing before parsing,
raw-byte preservation, and a normalized message model (evidence ID,
parsed addresses/dates, MIME structure tree, attachment inventory,
parser warnings, provenance).

v0.2: header forensics — Received-chain parsing (oldest-to-newest),
routing/auth-relevant header normalization, and observation-only
chain forensics (hop counts, timestamp order, private IPs, missing
data). Metadata claims are not proof: hostnames are never resolved
and nothing is fetched. Later phases (auth, URL triage, attachment
forensics, detection, intel, cases, reporting) plug into the models
and plugin registry defined here.

v0.3: authentication analysis — SPF/DKIM/DMARC header parsing
(Authentication-Results, DKIM-Signature, Received-SPF) with
observation-only alignment. Fully offline: no DNS, no signature
verification; everything describes what the headers claim.

v0.4: URL/domain extraction and triage — URLs from body text, HTML
links, and headers, decomposed locally with observation-only
analysis. Fully offline: never fetched, never resolved, shorteners
never expanded; observations are facts, never verdicts.
"""

__version__ = "0.4.0"
__author__ = "Pouya Shini Karim"
__license__ = "MIT"

from phishscope import auth, headers, parsers, urls
from phishscope.core import config, hashing, logging, models, plugins, results

__all__ = [
    "__version__",
    "auth",
    "config",
    "hashing",
    "headers",
    "logging",
    "models",
    "parsers",
    "plugins",
    "results",
    "urls",
]
