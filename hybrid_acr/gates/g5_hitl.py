"""Gate 5 - Human-in-the-Loop (HITL) Escalation Gate.

Proposal Table 2: human escalation for high-risk or ambiguous findings; metric =
review hrs / 100 LOC. RTA Theme 6 establishes the design tension every
participant navigated:
  - Mandatory human sign-off on EVERY finding is rejected as infeasible (P01:
    five engineers / 200 PRs per week cannot absorb it).
  - Advisory-only review with no audit trail is ALSO rejected (P02: "creates
    the appearance of AI oversight with none of the accountability").

The convergent solution is RISK-STRATIFIED escalation (P13: "governance
intensity should match the risk classification of the code"). This gate decides
the FINAL pipeline decision from all collected findings + the sensitivity of
the code path:

  - Any CRITICAL finding, OR any HIGH finding on a sensitive path  -> BLOCK
    (P02: critical findings block merge, no override except logged exception).
  - HIGH finding on a non-sensitive path, or MEDIUM on sensitive  -> ESCALATE
    (named reviewer, mandatory justification, logged to audit ledger).
  - Otherwise                                                      -> PASS.

The gate also estimates review burden (review hrs / 100 LOC) so the operational
overhead metric from the proposal is measurable.
"""
from __future__ import annotations

from .base import Gate
from ..models import Decision, Finding, GateResult, ReviewContext, Severity


# Rough per-finding human review cost, in hours, by severity. Used only to
# produce the operational-overhead metric; tunable per organisation.
REVIEW_HOURS = {
    Severity.CRITICAL: 0.75,
    Severity.HIGH: 0.5,
    Severity.MEDIUM: 0.25,
    Severity.LOW: 0.0,
    Severity.INFO: 0.0,
}


class HITLGate(Gate):
    gate_id = "G5"
    gate_name = "HITL Escalation Gate"

    def run(self, ctx: ReviewContext) -> GateResult:
        findings: list[Finding] = ctx.config.get("all_findings", [])
        loc = max(ctx.config.get("loc", 0), 1)

        actionable = [f for f in findings if f.severity >= Severity.MEDIUM]
        criticals = [f for f in actionable if f.severity >= Severity.CRITICAL]
        highs = [f for f in actionable if f.severity == Severity.HIGH]
        mediums = [f for f in actionable if f.severity == Severity.MEDIUM]

        if criticals or (highs and ctx.sensitive):
            decision = Decision.BLOCK
            reason = "critical finding" if criticals else "high-severity finding on sensitive path"
        elif highs or (mediums and ctx.sensitive):
            decision = Decision.ESCALATE
            reason = "high-severity finding" if highs else "medium finding on sensitive path"
        else:
            decision = Decision.PASS
            reason = "no actionable findings above threshold"

        review_hours = sum(REVIEW_HOURS[f.severity] for f in actionable)
        return GateResult(
            self.gate_id, self.gate_name, decision, findings=actionable,
            telemetry={
                "decision_reason": reason,
                "sensitive_path": ctx.sensitive,
                "actionable_findings": len(actionable),
                "critical": len(criticals), "high": len(highs), "medium": len(mediums),
                "estimated_review_hours": round(review_hours, 2),
                "review_hours_per_100_loc": round(review_hours / loc * 100, 3),
                # If ESCALATE/BLOCK, these fields would be filled by the human:
                "requires_named_reviewer": decision in (Decision.ESCALATE, Decision.BLOCK),
                "override_path": "logged-exception-only" if decision == Decision.BLOCK else None,
            },
        )
