"""Gate 3 - Constrained LLM Semantic Review.

Proposal Table 2: context-limited, system-prompted semantic analysis; metric =
hallucination rate. RTA Theme 1: target the logic-level detection gap (authz,
IDOR, SSRF, crypto-context) where SAST is weak -- NOT syntactic patterns.

Constraints enforced by THIS gate (not trusted from the model):
  - Context-window limit (truncate code to a configured char budget).
  - SAST findings from G1 are injected so the LLM "has less to invent"
    (P09's SAST -> LLM ordering result).
  - JSON-only output contract (P01/P03). Non-JSON output is treated as a gate
    failure -> ESCALATE (we never silently trust malformed output).
  - No autonomous remediation: the schema has no 'fix' field; any code-like
    content in rationales is ignored downstream.
"""
from __future__ import annotations

import json
import re

from .base import Gate
from ..llm_backend import LLMBackend, get_backend
from ..models import Decision, Finding, GateResult, ReviewContext, Severity, Source


class LLMReviewGate(Gate):
    gate_id = "G3"
    gate_name = "Constrained LLM Review"

    def __init__(self, backend: LLMBackend | None = None, context_char_limit: int = 12000) -> None:
        self.backend = backend or get_backend()
        self.context_char_limit = context_char_limit

    def _read_code(self, ctx: ReviewContext) -> str:
        chunks = []
        for path in ctx.files:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    chunks.append(f"# FILE: {path}\n{fh.read()}")
            except OSError:
                continue
        return "\n\n".join(chunks)[: self.context_char_limit]

    @staticmethod
    def _sast_summary(ctx: ReviewContext) -> str:
        prior = ctx.config.get("sast_findings", [])
        if not prior:
            return "(none)"
        return "; ".join(f"{f['rule_id']} [{f['cwe']}] L{f['line']}" for f in prior[:20])

    @staticmethod
    def _extract_json(raw: str) -> dict | None:
        """Enforce the JSON-only contract. Tolerate accidental fences, but if the
        payload is not a single parseable JSON object, fail closed (None)."""
        if raw is None:
            return None
        text = raw.strip()
        text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.MULTILINE).strip()
        try:
            obj = json.loads(text)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            # last resort: grab the first {...} block
            m = re.search(r"\{.*\}", text, re.DOTALL)
            if m:
                try:
                    obj = json.loads(m.group(0))
                    return obj if isinstance(obj, dict) else None
                except json.JSONDecodeError:
                    return None
            return None

    def run(self, ctx: ReviewContext) -> GateResult:
        code = self._read_code(ctx)
        if not code.strip():
            return GateResult(self.gate_id, self.gate_name, Decision.PASS,
                              telemetry={"backend": self.backend.name, "note": "no code"})

        raw = self.backend.review(code, self._sast_summary(ctx))
        parsed = self._extract_json(raw)

        # Contract violation: malformed output is itself a risk signal. RTA
        # Theme 2 warns against treating opaque AI output as trustworthy.
        if parsed is None or "findings" not in parsed:
            return GateResult(
                self.gate_id, self.gate_name, Decision.ESCALATE,
                telemetry={"backend": self.backend.name,
                           "contract_violation": True,
                           "raw_preview": (raw or "")[:200]},
            )

        findings: list[Finding] = []
        for item in parsed.get("findings", []):
            try:
                sev = Severity.from_str(item.get("severity", "LOW"))
            except KeyError:
                sev = Severity.LOW
            findings.append(Finding(
                rule_id=item.get("rule_id", "llm.unknown"),
                title=item.get("title", "LLM finding"),
                severity=sev, source=Source.LLM,
                file=ctx.target_path, line=int(item.get("line", 0) or 0),
                cwe=item.get("cwe", ""),
                message=item.get("rationale", ""),
                verified=False,  # CRITICAL: LLM findings are UNVERIFIED until G4
                metadata={"confidence": item.get("confidence")},
            ))

        # G3 itself never blocks or passes definitively -- it produces findings.
        # Verification (G4) and routing (G5) decide. So G3 returns PASS to mean
        # "produced output cleanly"; the findings carry the weight forward.
        return GateResult(
            self.gate_id, self.gate_name, Decision.PASS, findings=findings,
            telemetry={
                "backend": self.backend.name,
                "context_chars": len(code),
                "context_truncated": len(code) >= self.context_char_limit,
                "llm_findings": len(findings),
            },
        )
