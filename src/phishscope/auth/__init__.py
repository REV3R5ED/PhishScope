"""PhishScope v0.3: SPF/DKIM/DMARC authentication analysis (offline).

Parses ``Authentication-Results``, ``DKIM-Signature``, and
``Received-SPF`` headers and derives observation-only facts (result
triples, alignment, conflicts, missing data). The hard offline
boundary: no DNS lookups are ever performed — no SPF record
fetching, no DKIM key retrieval, no DMARC policy fetching — and DKIM
signatures are never cryptographically verified. Everything here
describes what the headers *claim*; metadata claims are not proof.
"""

from phishscope.auth.analysis import PARSER_NAME, PARSER_VERSION, analyze_auth
from phishscope.auth.models import (
    AuthAnalysis,
    AuthMethodResult,
    AuthObservation,
    DkimSignature,
    ReceivedSpf,
)
from phishscope.core.plugins import ModuleInfo, register

__all__ = [
    "PARSER_NAME",
    "PARSER_VERSION",
    "AuthAnalysis",
    "AuthMethodResult",
    "AuthObservation",
    "DkimSignature",
    "ReceivedSpf",
    "analyze_auth",
]

register(
    ModuleInfo(
        name="auth",
        description="SPF/DKIM/DMARC authentication analysis (offline): "
        "Authentication-Results / DKIM-Signature / Received-SPF parsing, "
        "alignment observations, no DNS, no signature verification (v0.3)",
        version="0.3.0",
        commands=["auth"],
    )
)
