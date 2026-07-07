"""Gate 0 - Secrets Scanner.

Proposal Table 2: pre-flight hard-coded secret detection; key metric =
secret-leakage rate. Motivated by GitGuardian (2025): 6.4% secret-leakage rate
in Copilot-augmented repos, 25% YoY rise in hard-coded secrets.

A hard-coded secret is a BLOCK with no override path: it is deterministic,
high-confidence, and there is no legitimate reason to merge a live credential.
This is the cheapest gate and runs first so the LLM (G3) never ingests secrets.
"""
from __future__ import annotations

import os
import re

from .base import Gate
from ..models import Decision, Finding, GateResult, ReviewContext, Severity, Source


# Pattern name -> (regex, cwe). Deliberately conservative, high-signal patterns;
# a production gate would delegate to gitleaks/trufflehog rule packs.
SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("aws-access-key-id", re.compile(r"AKIA[0-9A-Z]{16}"), "CWE-798"),
    ("aws-secret-access-key",
     re.compile(r"(?i)aws.{0,20}?(secret|private).{0,3}?['\"][0-9a-zA-Z/+]{40}['\"]"), "CWE-798"),
    ("private-key-block",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "CWE-321"),
    ("generic-api-key",
     re.compile(r"(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['\"][^'\"]{12,}['\"]"),
     "CWE-798"),
    ("slack-token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), "CWE-798"),
    ("github-pat", re.compile(r"ghp_[0-9A-Za-z]{36}"), "CWE-798"),
]

# Lines containing these markers are treated as test/example fixtures and
# downgraded to INFO -- otherwise the gate's own test fixtures would block CI.
PLACEHOLDER_HINTS = ("example", "dummy", "placeholder", "redacted", "your-", "xxxx", "<", "fake")


class SecretsScannerGate(Gate):
    gate_id = "G0"
    gate_name = "Secrets Scanner"

    def run(self, ctx: ReviewContext) -> GateResult:
        findings: list[Finding] = []
        scanned = 0
        for path in ctx.files:
            if not os.path.isfile(path):
                continue
            scanned += 1
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    lines = fh.readlines()
            except OSError:
                continue
            for lineno, text in enumerate(lines, start=1):
                low = text.lower()
                for name, pattern, cwe in SECRET_PATTERNS:
                    if pattern.search(text):
                        placeholder = any(h in low for h in PLACEHOLDER_HINTS)
                        findings.append(Finding(
                            rule_id=f"secret.{name}",
                            title=f"Hard-coded secret: {name}",
                            severity=Severity.INFO if placeholder else Severity.CRITICAL,
                            source=Source.SECRETS,
                            file=path,
                            line=lineno,
                            cwe=cwe,
                            message=("Likely placeholder/test value." if placeholder
                                     else "Live credential pattern detected. Remove and rotate."),
                            verified=not placeholder,  # deterministic match = verified
                            metadata={"placeholder": placeholder},
                        ))

        real = [f for f in findings if f.severity >= Severity.CRITICAL]
        decision = Decision.BLOCK if real else Decision.PASS
        return GateResult(
            gate_id=self.gate_id,
            gate_name=self.gate_name,
            decision=decision,
            findings=findings,
            telemetry={
                "files_scanned": scanned,
                "secrets_found": len(real),
                "placeholders_ignored": len(findings) - len(real),
                # secret-leakage rate proxy: real secrets per file scanned
                "secret_leakage_rate": round(len(real) / scanned, 4) if scanned else 0.0,
            },
            aborted_pipeline=bool(real),  # never let a live secret reach the LLM
        )
