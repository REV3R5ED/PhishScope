"""Message parsers for PhishScope.

v0.1 ships the safe .eml/MIME parser (:mod:`phishscope.parsers.safe_eml`).
Later phases add header, auth, URL, and attachment parsers here.
"""

from phishscope.parsers import safe_eml

__all__ = ["safe_eml"]
