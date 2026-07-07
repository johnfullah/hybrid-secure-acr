"""Gate 4 - Output Validation Filter.

Proposal Table 2: response validation against trusted vulnerability databases;
metric = mis-recommendation rate. RTA Theme 1 (DG-02): "wrong remediation /
insecure AI fix" -- P02 called it "more dangerous than a missed detection,
because it creates false confidence." RTA Theme 6: output-validation gate
(CVE/CWE cross-reference against NVD/OSV to remove hallucinations) specified by
11/16.

This gate validates each UNVERIFIED LLM finding (from G3) against:
  1. A trusted CWE registry (is the cited CWE real?). A fabricated CWE is a
     strong hallucination signal -> drop the finding.
  2. A confidence floor (configurable). Low-confidence LLM findings are demoted
     to advisory (kept in the record, but not allowed to block/escalate) --
     this is the "confidence thresholding" RTA Theme 3 credits with restoring
     developer engagement (P07).

In a production deployment, step 1 would query the live NVD/OSV APIs; here we
ship a static snapshot of the CWE identifiers the framework targets, which is
sufficient to detect fabricated identifiers and keeps the prototype offline-runnable.
"""
from __future__ import annotations

from .base import Gate
from ..models import Decision, GateResult, ReviewContext, Severity, Source


# Trusted CWE snapshot: the logic-level + common pattern classes named across
# both source documents. A finding citing a CWE outside any recognised registry
# is treated as a likely hallucination.
KNOWN_CWES: set[str] = {
    "CWE-79", "CWE-89", "CWE-862", "CWE-863", "CWE-639", "CWE-918", "CWE-307",
    "CWE-327", "CWE-269", "CWE-798", "CWE-321", "CWE-22", "CWE-78", "CWE-352",
    "CWE-502", "CWE-611", "CWE-94", "CWE-287", "CWE-200", "CWE-732",
}


class OutputFilterGate(Gate):
    gate_id = "G4"
    gate_name = "Output Validation Filter"

    def __init__(self, confidence_floor: float = 0.5) -> None:
        self.confidence_floor = confidence_floor

    def run(self, ctx: ReviewContext) -> GateResult:
        incoming = ctx.config.get("llm_findings_objs", [])
        kept, dropped_hallucination, demoted_lowconf = [], 0, 0

        for f in incoming:
            cwe = (f.cwe or "").upper().strip()
            # 1. Hallucination check: unknown/fabricated CWE -> drop.
            if cwe and cwe not in KNOWN_CWES:
                dropped_hallucination += 1
                continue
            # 2. Confidence thresholding.
            conf = f.metadata.get("confidence")
            if conf is not None and float(conf) < self.confidence_floor:
                f.severity = Severity.INFO  # demote to advisory
                f.metadata["demoted"] = True
                demoted_lowconf += 1
            # Passing validation marks the finding verified (cross-referenced).
            f.verified = True
            kept.append(f)

        n_in = len(incoming)
        mis_rate = round(dropped_hallucination / n_in, 4) if n_in else 0.0
        return GateResult(
            self.gate_id, self.gate_name, Decision.PASS, findings=kept,
            telemetry={
                "llm_findings_in": n_in,
                "kept": len(kept),
                "dropped_hallucination": dropped_hallucination,
                "demoted_low_confidence": demoted_lowconf,
                "mis_recommendation_rate": mis_rate,
                "confidence_floor": self.confidence_floor,
            },
        )
