"""PhishScope — email and phishing forensics.

Trace the message. Expose the evidence.

v0.1: safe .eml/MIME parser (stdlib ``email`` only — nothing executes,
nothing renders, nothing fetches), SHA-256 hashing before parsing,
raw-byte preservation, and a normalized message model (evidence ID,
parsed addresses/dates, MIME structure tree, attachment inventory,
parser warnings, provenance). Later phases (header forensics, auth,
URL triage, attachment forensics, detection, intel, cases, reporting)
plug into the models and plugin registry defined here.
"""

__version__ = "0.1.0"
__author__ = "Pouya Shini Karim"
__license__ = "MIT"

from phishscope import parsers
from phishscope.core import config, hashing, logging, models, plugins, results

__all__ = [
    "__version__",
    "config",
    "hashing",
    "logging",
    "models",
    "parsers",
    "plugins",
    "results",
]
