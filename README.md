# Hybrid-Secure-ACR

A runnable prototype of the **Hybrid AI–Human Security Framework for LLM-based
Automated Code Review**, implementing the six-gate sequential CI/CD architecture
specified in the WP4 research proposal (RO3) and grounded in the empirical
findings of the WP3 Reflexive Thematic Analysis.

It runs two ways: as a **Python CLI engine** (locally, now) and as a
**GitHub Actions workflow** (CI-native). The LLM gate is switchable between a
**mock backend** (offline, no key — the default) and a **real Anthropic API
call**, via one environment variable.

## The six gates

| Gate | Component | What it does | Grounded in |
|---|---|---|---|
| **G0** | Secrets Scanner | Pre-flight hard-coded secret detection; **blocks before the LLM sees anything** | GitGuardian (2025) leakage rates |
| **G1** | SAST (Semgrep + Bandit) | Deterministic, rule-based scan; runs **before** the LLM | RTA Theme 6 — 16/16 rejected LLM-first; P09's SAST→LLM result |
| **G2** | Adversarial Input Filter | Screens PR text + code comments for prompt injection; **aborts before G3** | RTA Theme 4 — the critical missing control; P01/P03 confirmed injections |
| **G3** | Constrained LLM Review | Context-limited, JSON-only, no autonomous fixes; targets logic-level flaws (CWE-639/862/863/918) | RTA Theme 1 detection gap; Theme 6 constraints |
| **G4** | Output Validation Filter | Cross-references LLM findings against a trusted CWE registry; drops hallucinations, demotes low-confidence | RTA Theme 1 DG-02; Theme 6 (11/16) |
| **G5** | HITL Escalation Gate | Risk-stratified routing: BLOCK / ESCALATE / PASS by severity × path sensitivity | RTA Theme 6 — the central design tension |

Cross-cutting: every gate result is written to a **hash-chained, tamper-evident
audit ledger** (RTA Theme 5 — audit-trail inadequacy was the #1 governance gap,
16/16).

## Quick start

```bash
pip install -r requirements.txt

# Run the full hybrid pipeline over the bundled fixtures
python -m hybrid_acr.cli scan fixtures/vuln_idor.py --sensitive
python -m hybrid_acr.cli scan fixtures/vuln_injection.py
python -m hybrid_acr.cli scan fixtures/clean_safe.py

# Verify the audit trail is intact
python -m hybrid_acr.cli verify-ledger audit/ledger.jsonl

# Run the test suite (offline, mock LLM)
pytest
```

Exit codes map onto CI merge control: `0 = PASS`, `1 = ESCALATE`, `2 = BLOCK`.

## Switching to a real LLM (Gate 3)

```bash
export ACR_LLM_BACKEND=anthropic
export ANTHROPIC_API_KEY=sk-ant-...
export ACR_LLM_MODEL=claude-sonnet-4-6   # optional
python -m hybrid_acr.cli scan path/to/code
```

With `ACR_LLM_BACKEND` unset (or `mock`), the pipeline uses a deterministic stub
— no key, no network — which is what the test suite uses.

## The three evaluation arms (RQ3 / WP5)

The pipeline supports the comparison configurations from the proposal:

```bash
python -m hybrid_acr.cli scan fixtures/vuln_injection.py --config sast-only
python -m hybrid_acr.cli scan fixtures/vuln_injection.py --config llm-augmented
python -m hybrid_acr.cli scan fixtures/vuln_injection.py --config hybrid
```

On the injection fixture these produce **PASS / BLOCK / ESCALATE** respectively:
`sast-only` has no semantic awareness, `llm-augmented` only reacts *after*
feeding poisoned input to the model (the Theme 4 gap), and `hybrid` catches the
injection at G2 *before* the LLM runs.

## Layout

```
hybrid_acr/           # the engine
  models.py           # shared types (Finding, Severity, Decision, ...)
  audit.py            # hash-chained immutable ledger
  llm_backend.py      # mock + Anthropic backends, constrained system prompt
  pipeline.py         # six-gate orchestrator
  cli.py              # command-line interface
  gates/g0..g5        # one module per gate
fixtures/             # deliberately vulnerable + clean test inputs
tests/                # pytest suite (offline)
rulesets/             # Semgrep ruleset (secondary artefact)
prompts/              # LLM system prompt template (secondary artefact)
.github/workflows/    # GitHub Actions wrapper (CI-native artefact)
```

## Scope and honesty about limitations

This is a **research prototype**, not a production security tool. The injection
filter (G2) is a regex+heuristic implementation of P07's "Prompt Guard" pattern
and will have false positives/negatives; the CWE registry in G4 is a static
snapshot, not a live NVD/OSV query; and the mock LLM recognises only the
fixture-shaped flaws. These are deliberate, documented simplifications that keep
the prototype offline-runnable while faithfully exercising the framework's
control flow — which is what the WP5 evaluation measures.
