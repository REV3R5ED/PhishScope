"""Header and Received-chain forensics (v0.2).

Parses routing/auth-relevant headers from the raw message bytes and
normalizes the Received chain oldest-to-newest. Every statement this
package makes is an *observation* — what the headers claim — never a
verdict. Metadata claims are not proof of where or how a message was
created: hostnames are never resolved (no DNS, no network), timestamps
are reported verbatim with an optional UTC normalization, and a
timezone is never invented.

Modules:
- :mod:`phishscope.headers.models` — ReceivedHop / HeaderObservation /
  HeaderAnalysis dataclasses.
- :mod:`phishscope.headers.received` — tolerant Received-header parser.
- :mod:`phishscope.headers.analysis` — whole-message header analysis
  with observation-only chain forensics.
"""

from phishscope.headers import analysis, models, received

__all__ = ["analysis", "models", "received"]
