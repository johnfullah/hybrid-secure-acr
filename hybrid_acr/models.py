"""Core data models for the Hybrid-Secure-ACR pipeline.

These types are shared across all six gates (G0-G5). Keeping them in one
place means every gate speaks the same vocabulary about findings, severity,
and routing decisions -- which is what makes the immutable audit ledger
(Gate 5) able to reconstruct a coherent record of every pipeline run.
"""
from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


class Severity(enum.IntEnum):
    """Ordered so that comparisons (>=) work for escalation thresholds."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        return cls[value.strip().upper()] if value else cls.INFO


class Decision(enum.Enum):
    """Final routing decision for a pipeline run (RTA Theme 6: structural gates)."""
    PASS = "PASS"               # clean, auto-merge allowed
    BLOCK = "BLOCK"             # hard stop, no override path
    ESCALATE = "ESCALATE"       # route to human-in-the-loop (Gate 5)
    ABORT = "ABORT"             # pipeline aborted by a gate (e.g. injection detected)


class Source(enum.Enum):
    """Provenance of a finding. RTA Theme 3 stresses that LLM findings must be
    distinguishable from deterministic SAST findings, because they lack the
    deterministic provenance developers use to build trust priors."""
    SECRETS = "secrets-scanner"      # G0
    SAST = "sast"                    # G1 (Semgrep / Bandit)
    INPUT_FILTER = "input-filter"    # G2
    LLM = "llm-review"               # G3 (probabilistic - treat with caution)
    OUTPUT_FILTER = "output-filter"  # G4


@dataclass
class Finding:
    """A single security finding from any gate."""
    rule_id: str
    title: str
    severity: Severity
    source: Source
    file: str = ""
    line: int = 0
    cwe: str = ""                       # e.g. "CWE-862"
    message: str = ""
    # Whether this finding has been corroborated against a trusted source
    # (NVD/OSV/SAST). RTA Theme 1 (DG-02) + Theme 6 output-validation gate:
    # an unverified LLM finding must never be trusted like a verified one.
    verified: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.name
        d["source"] = self.source.value
        return d


@dataclass
class GateResult:
    """Outcome of running a single gate."""
    gate_id: str                         # "G0".."G5"
    gate_name: str
    decision: Decision
    findings: list[Finding] = field(default_factory=list)
    # Free-form, gate-specific telemetry. Stored verbatim in the audit ledger.
    telemetry: dict[str, Any] = field(default_factory=dict)
    aborted_pipeline: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "gate_name": self.gate_name,
            "decision": self.decision.value,
            "aborted_pipeline": self.aborted_pipeline,
            "findings": [f.to_dict() for f in self.findings],
            "telemetry": self.telemetry,
        }


@dataclass
class ReviewContext:
    """Everything a gate needs to do its job, threaded through the pipeline."""
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    target_path: str = ""                 # file or directory under review
    files: list[str] = field(default_factory=list)
    # Untrusted free text that travels WITH the change: PR description, commit
    # messages, code comments. RTA Theme 4: this is the prompt-injection surface.
    untrusted_text: str = ""
    # Sensitivity classification of the code path (RTA Theme 6: risk-stratified
    # escalation). Paths like /crypto/ or /pci/ get stricter routing.
    sensitive: bool = False
    config: dict[str, Any] = field(default_factory=dict)
