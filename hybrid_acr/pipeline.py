"""Sequential six-gate pipeline orchestrator.

Implements the defence-in-depth ordering from the proposal (Table 2) and
validated by RTA Theme 6 (sequential SAST -> LLM, not LLM-first):

    G0 Secrets  ->  G1 SAST  ->  G2 Input Filter  ->  G3 LLM Review
                                         ->  G4 Output Filter  ->  G5 HITL

Cross-cutting: every gate result is written to the immutable audit ledger
(RTA Theme 5 / Gate 5 audit requirement) as it runs, so even an aborted run
leaves a complete, tamper-evident record.

Three configurations are supported for the WP5-style comparison (RQ3):
  - "sast-only"   : G0 + G1 only (baseline)
  - "llm-augmented": G0 + G1 + G3 (unconstrained: no input/output filter, no
                     risk-stratified HITL) -- the "naive" comparison arm
  - "hybrid"      : all six gates (the framework under test)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .audit import AuditLedger
from .gates import (HITLGate, InputFilterGate, LLMReviewGate, OutputFilterGate,
                    SASTGate, SecretsScannerGate)
from .llm_backend import LLMBackend
from .models import Decision, Finding, GateResult, ReviewContext, Severity, Source


@dataclass
class PipelineResult:
    run_id: str
    config: str
    decision: Decision
    gate_results: list[GateResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    aborted_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "config": self.config,
            "decision": self.decision.value,
            "aborted_at": self.aborted_at,
            "gate_results": [g.to_dict() for g in self.gate_results],
            "summary": self.summary(),
        }

    def summary(self) -> dict[str, Any]:
        by_source: dict[str, int] = {}
        for f in self.findings:
            by_source[f.source.value] = by_source.get(f.source.value, 0) + 1
        return {
            "total_findings": len(self.findings),
            "findings_by_source": by_source,
            "max_severity": max((f.severity for f in self.findings),
                                default=Severity.INFO).name,
        }


class HybridACRPipeline:
    def __init__(self, ledger: AuditLedger, config: str = "hybrid",
                 llm_backend: LLMBackend | None = None,
                 confidence_floor: float = 0.5) -> None:
        assert config in ("sast-only", "llm-augmented", "hybrid")
        self.config = config
        self.ledger = ledger
        self.g0 = SecretsScannerGate()
        self.g1 = SASTGate()
        self.g2 = InputFilterGate()
        self.g3 = LLMReviewGate(backend=llm_backend)
        self.g4 = OutputFilterGate(confidence_floor=confidence_floor)
        self.g5 = HITLGate()

    def _log(self, gr: GateResult, run_id: str) -> None:
        self.ledger.append("gate_result", {"run_id": run_id, **gr.to_dict()})

    def run(self, ctx: ReviewContext) -> PipelineResult:
        self.ledger.append("run_started", {
            "run_id": ctx.run_id, "config": self.config,
            "target": ctx.target_path, "files": ctx.files,
            "sensitive": ctx.sensitive, "started_at": ctx.started_at,
        })
        result = PipelineResult(run_id=ctx.run_id, config=self.config,
                                decision=Decision.PASS)
        all_findings: list[Finding] = []

        # G0 Secrets (all configs)
        g0 = self.g0.run(ctx)
        result.gate_results.append(g0); self._log(g0, ctx.run_id)
        all_findings += g0.findings
        if g0.aborted_pipeline:
            return self._finalise(result, all_findings, Decision.BLOCK, "G0", ctx)

        # G1 SAST (all configs)
        g1 = self.g1.run(ctx)
        result.gate_results.append(g1); self._log(g1, ctx.run_id)
        all_findings += g1.findings
        ctx.config["sast_findings"] = [f.to_dict() for f in g1.findings]

        if self.config == "sast-only":
            final = Decision.BLOCK if any(f.severity >= Severity.HIGH for f in g1.findings) else Decision.PASS
            return self._finalise(result, all_findings, final, None, ctx)

        # G2 Input Filter (hybrid only -- the unconstrained arm deliberately omits it)
        if self.config == "hybrid":
            g2 = self.g2.run(ctx)
            result.gate_results.append(g2); self._log(g2, ctx.run_id)
            all_findings += g2.findings
            if g2.aborted_pipeline:
                # Injection detected: do NOT let the LLM run. Route to human.
                return self._finalise(result, all_findings, Decision.ESCALATE, "G2", ctx)

        # G3 Constrained LLM Review (llm-augmented + hybrid)
        g3 = self.g3.run(ctx)
        result.gate_results.append(g3); self._log(g3, ctx.run_id)

        if self.config == "hybrid":
            # G4 Output Filter validates G3's findings before they count.
            ctx.config["llm_findings_objs"] = g3.findings
            g4 = self.g4.run(ctx)
            result.gate_results.append(g4); self._log(g4, ctx.run_id)
            all_findings += g4.findings  # validated LLM findings
            if g3.decision == Decision.ESCALATE:  # contract violation in G3
                return self._finalise(result, all_findings, Decision.ESCALATE, "G3", ctx)
        else:
            # llm-augmented arm: trust LLM findings directly, no validation.
            all_findings += g3.findings

        # G5 HITL routing (hybrid uses risk-stratification; llm-augmented uses
        # a naive "block on any high" rule to model the unconstrained baseline).
        if self.config == "hybrid":
            ctx.config["all_findings"] = all_findings
            ctx.config["loc"] = self._count_loc(ctx)
            g5 = self.g5.run(ctx)
            result.gate_results.append(g5); self._log(g5, ctx.run_id)
            return self._finalise(result, all_findings, g5.decision, None, ctx)
        else:
            final = Decision.BLOCK if any(f.severity >= Severity.HIGH for f in all_findings) else Decision.PASS
            return self._finalise(result, all_findings, final, None, ctx)

    @staticmethod
    def _count_loc(ctx: ReviewContext) -> int:
        total = 0
        for path in ctx.files:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    total += sum(1 for _ in fh)
            except OSError:
                pass
        return total

    def _finalise(self, result: PipelineResult, findings: list[Finding],
                  decision: Decision, aborted_at: str | None,
                  ctx: ReviewContext) -> PipelineResult:
        result.findings = findings
        result.decision = decision
        result.aborted_at = aborted_at
        self.ledger.append("run_completed", {
            "run_id": result.run_id, "config": self.config,
            "decision": decision.value, "aborted_at": aborted_at,
            "summary": result.summary(),
        })
        return result
