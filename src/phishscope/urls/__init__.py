"""URL/domain extraction and triage (v0.4).

Fully offline: URLs are extracted from body text, HTML attributes and
text (structural parse only — never rendered), and all header values;
each is decomposed locally (scheme/host/port/path/query, IDNA forms,
IP-literal detection, naive registered domain, shortener
recognition). URLs are never fetched, hostnames are never resolved,
shorteners are never expanded.

Every statement this package makes is an *observation* — what the
message contains — never a verdict (heuristic judgments are v0.6 work
with explicit limitations).

Modules:
- :mod:`phishscope.urls.models` — UrlRecord / UrlSource /
  UrlObservation / UrlAnalysis dataclasses.
- :mod:`phishscope.urls.defang` — defang/undefang, defanged-source
  recognition, URL candidate regex.
- :mod:`phishscope.urls.decompose` — local URL decomposition, IDNA,
  shortener list, dedup keys.
- :mod:`phishscope.urls.extract` — read-only candidate extraction
  from raw bytes.
- :mod:`phishscope.urls.observations` — observation-only forensics.
- :mod:`phishscope.urls.analysis` — whole-message URL analysis.
"""

from phishscope.core.plugins import ModuleInfo, register
from phishscope.urls import analysis, decompose, defang, extract, models, observations
from phishscope.urls.analysis import PARSER_NAME, PARSER_VERSION, analyze_urls
from phishscope.urls.models import UrlAnalysis, UrlObservation, UrlRecord, UrlSource

__all__ = [
    "PARSER_NAME",
    "PARSER_VERSION",
    "UrlAnalysis",
    "UrlObservation",
    "UrlRecord",
    "UrlSource",
    "analysis",
    "analyze_urls",
    "decompose",
    "defang",
    "extract",
    "models",
    "observations",
]

register(
    ModuleInfo(
        name="urls",
        description="URL/domain extraction and triage (offline): body text, "
        "HTML links, and header URLs extracted and decomposed locally "
        "(never fetched, never resolved), observation-only analysis (v0.4)",
        version="0.4.0",
        commands=["urls"],
    )
)
