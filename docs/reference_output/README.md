# Reference output (known-good local run)

Captured from the prototype running locally with the mock LLM backend. Use these
to confirm your own run matches before capturing Appendix I screenshots.

- `claude_response.json` — Gate 3 JSON contract response for fixtures/vuln_idor.py
- `semgrep.json`         — Semgrep findings (raw JSON) over fixtures/
- `bandit.json`          — Bandit findings (raw JSON) over fixtures/
- `pipeline_run.txt`     — full six-gate pipeline console output (decision: ESCALATE)
- `ledger.jsonl`         — hash-chained audit ledger from the run

Note: a live Anthropic model will word the `rationale`/`title` differently, but
the JSON schema is identical because Gate 3 enforces the output contract.
