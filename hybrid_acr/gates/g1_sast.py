"""Gate 1 - Deterministic SAST (Semgrep + Bandit).

Proposal Table 2: deterministic rule-based vulnerability scan; metric = TPR/FPR.
RTA Theme 6: SAST as MANDATORY FIRST analytical gate was specified by 16/16
participants -- all explicitly rejected LLM-first architectures. P09's internal
experiment found SAST -> LLM consistently beats LLM -> SAST because the LLM
"has less to invent if it's commenting on real SAST findings." So G1 runs
before G3, and its findings are fed into the LLM's context.

This gate shells out to the real `semgrep` and `bandit` binaries when present,
and degrades gracefully (telemetry notes the tool was unavailable) when they are
not, so the pipeline remains runnable in constrained environments.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

from .base import Gate
from ..models import Decision, Finding, GateResult, ReviewContext, Severity, Source


_SEMGREP_SEV = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}
_BANDIT_SEV = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


class SASTGate(Gate):
    gate_id = "G1"
    gate_name = "SAST (Semgrep + Bandit)"

    def __init__(self, semgrep_config: str = "p/ci", timeout: int = 180) -> None:
        self.semgrep_config = semgrep_config
        self.timeout = timeout

    def run(self, ctx: ReviewContext) -> GateResult:
        findings: list[Finding] = []
        telemetry: dict = {"semgrep": "skipped", "bandit": "skipped"}

        target = ctx.target_path or (ctx.files[0] if ctx.files else ".")

        if shutil.which("semgrep"):
            findings += self._run_semgrep(target, telemetry)
        if shutil.which("bandit"):
            findings += self._run_bandit(target, telemetry)

        high = [f for f in findings if f.severity >= Severity.HIGH]
        # SAST findings are deterministic -> verified=True. High-severity SAST
        # blocks; medium/low pass through (they may still be raised by later
        # gates or surfaced advisorily).
        decision = Decision.BLOCK if high else Decision.PASS
        telemetry.update({
            "total_findings": len(findings),
            "high_severity": len(high),
        })
        return GateResult(
            gate_id=self.gate_id, gate_name=self.gate_name,
            decision=decision, findings=findings, telemetry=telemetry,
        )

    def _run_semgrep(self, target: str, telemetry: dict) -> list[Finding]:
        cmd = ["semgrep", "scan", "--config", self.semgrep_config,
               "--json", "--quiet", "--metrics=off", target]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            data = json.loads(proc.stdout or "{}")
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
            telemetry["semgrep"] = f"error: {exc.__class__.__name__}"
            return []
        out = []
        for r in data.get("results", []):
            sev = _SEMGREP_SEV.get(r.get("extra", {}).get("severity", "INFO"), Severity.LOW)
            meta = r.get("extra", {}).get("metadata", {})
            cwe = ""
            cwe_field = meta.get("cwe")
            if isinstance(cwe_field, list) and cwe_field:
                cwe = str(cwe_field[0]).split(":")[0].strip()
            elif isinstance(cwe_field, str):
                cwe = cwe_field.split(":")[0].strip()
            out.append(Finding(
                rule_id=r.get("check_id", "semgrep.unknown"),
                title=r.get("extra", {}).get("message", "Semgrep finding")[:120],
                severity=sev, source=Source.SAST,
                file=r.get("path", ""), line=r.get("start", {}).get("line", 0),
                cwe=cwe, message=r.get("extra", {}).get("message", ""),
                verified=True, metadata={"tool": "semgrep"},
            ))
        telemetry["semgrep"] = f"ok ({len(out)} findings)"
        return out

    def _run_bandit(self, target: str, telemetry: dict) -> list[Finding]:
        cmd = ["bandit", "-r", "-f", "json", "-q", target]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            data = json.loads(proc.stdout or "{}")
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
            telemetry["bandit"] = f"error: {exc.__class__.__name__}"
            return []
        out = []
        for r in data.get("results", []):
            sev = _BANDIT_SEV.get(r.get("issue_severity", "LOW"), Severity.LOW)
            cwe = ""
            cwe_obj = r.get("issue_cwe") or {}
            if isinstance(cwe_obj, dict) and cwe_obj.get("id"):
                cwe = f"CWE-{cwe_obj['id']}"
            out.append(Finding(
                rule_id=f"bandit.{r.get('test_id', 'unknown')}",
                title=r.get("test_name", "Bandit finding"),
                severity=sev, source=Source.SAST,
                file=r.get("filename", ""), line=r.get("line_number", 0),
                cwe=cwe, message=r.get("issue_text", ""),
                verified=True, metadata={"tool": "bandit"},
            ))
        telemetry["bandit"] = f"ok ({len(out)} findings)"
        return out
