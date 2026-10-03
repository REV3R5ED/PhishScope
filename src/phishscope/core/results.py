"""Shared result envelope and exit codes for the PhishScope CLI.

Conventions (stable across phases):
- exit 0: ok, no warnings
- exit 1: ok, but the analysis produced parser warnings / findings
- exit 2: error (unusable input, rejected by a safety bound, crash guard)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


@dataclass
class Finding:
    """A single recorded observation (v0.1: parser-level only)."""

    rule_id: str
    severity: str  # "info" | "low" | "medium" | "high"
    confidence: int  # 0-100, certainty about the observation, never intent
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "detail": self.detail,
            "evidence": self.evidence,
        }


@dataclass
class Result:
    """Envelope returned by every CLI command."""

    status: str  # "ok" | "error"
    command: str
    message: dict[str, Any] | None = None
    errors: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        from phishscope import __version__

        return {
            "tool": "phishscope",
            "version": __version__,
            "status": self.status,
            "command": self.command,
            "message": self.message,
            "findings": [f.to_dict() for f in self.findings],
            "errors": list(self.errors),
        }


def exit_code_for(result: Result, warnings_present: bool = False) -> int:
    """Map a result to a process exit code."""
    if result.status == "error" or result.errors:
        return EXIT_ERROR
    if result.findings or warnings_present:
        return EXIT_FINDINGS
    return EXIT_OK
