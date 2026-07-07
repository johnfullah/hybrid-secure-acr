# Appendix I — Screenshot Capture Guide

This guide walks you through producing **genuine** screenshots for Appendix I of
the dissertation. Every screenshot is a capture of the prototype actually
running on your own GitHub repository and (optionally) your own Anthropic API
key. Nothing here is a mock-up — that matters for research integrity, and it
means an examiner can reconcile run IDs, timestamps and commit hashes if asked.

You will produce five screenshots:

| # | Appendix I item | Where it is captured | Needs |
|---|-----------------|----------------------|-------|
| 1 | GitHub Actions execution | Actions tab, workflow run graph + logs | GitHub repo |
| 2 | Gitleaks detection | `Gitleaks secret scan` step log / job summary | GitHub repo |
| 3 | Semgrep / Bandit results | `Semgrep SAST` and `Bandit SAST` step logs | GitHub repo |
| 4 | Claude JSON response | `Claude constrained review` step log | Anthropic API key (optional) |
| 5 | GitHub Environment approval | "Review pending deployments" screen | GitHub repo + Environment rule |

There is also a **local reference output** set in `docs/reference_output/` so you
can confirm your run matches known-good output before you screenshot.

---

## Part A — One-time repository setup

### A1. Create the repository and push the prototype

```bash
# from the unzipped project root (contains hybrid_acr/, fixtures/, .github/ ...)
git init
git add .
git commit -m "Hybrid-Secure-ACR prototype (WP4) + Appendix I demo workflow"
git branch -M main
# create an EMPTY repo on github.com first (no README), then:
git remote add origin https://github.com/<your-username>/hybrid-secure-acr.git
git push -u origin main
```

> The fixtures under `fixtures/` contain **fake** credentials created only to
> trip the secret scanner. They grant no access. This is stated in the file
> header of `fixtures/vuln_secret.py` so a reviewer sees it immediately.

### A2. (Screenshot #4 only) Add your Anthropic API key

If you want the Claude step to call the real model rather than the deterministic
mock, add the key as a repository secret:

1. Repo → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**
2. Name: `ANTHROPIC_API_KEY`  ·  Value: your key (`sk-ant-...`)
3. (optional) add a **variable** `ACR_LLM_MODEL` = `claude-sonnet-4-6`

If you skip this, the Claude step still runs and prints valid JSON, and its log
prints `Backend: mock`. For the dissertation, using the real key gives a
stronger figure — capture the `Backend: anthropic` line in the same screenshot.

### A3. (Screenshot #5 only) Create the approval Environment

1. Repo → **Settings** → **Environments** → **New environment**
2. Name it exactly `security-review`
3. Enable **Required reviewers**, add yourself (or a second account), **Save**

This is what makes the pipeline physically pause and show the approval screen
when a change escalates.

---

## Part B — Trigger the run

The workflow is `.github/workflows/appendix-i-demo.yml`. Trigger it manually:

1. Repo → **Actions** tab
2. Left sidebar → **Hybrid-Secure-ACR (Appendix I demo)**
3. **Run workflow** → leave config as `hybrid` → **Run workflow**

The run scans `fixtures/vuln_idor.py`, which produces a HIGH logic-level finding
(CWE-639) and therefore an **ESCALATE** decision — this is what triggers the
approval job. (The vulnerable-secret and SQLi fixtures feed the Gitleaks and
Semgrep/Bandit steps.)

---

## Part C — Capture each screenshot

### Screenshot #1 — GitHub Actions execution

- Open the run from the Actions tab.
- Capture the **job graph** showing `Security scan (G0-G4)` completed and
  `Human-in-the-loop approval (Gate 5)` **waiting**.
- Also capture the expanded left-hand step list of the `scan` job (all the
  green ticks: checkout, Gitleaks, Semgrep, Bandit, Claude, pipeline).
- **What good looks like:** the run header shows your repo, the commit SHA, the
  trigger ("manually run by <you>"), and a timestamp. Keep those visible — they
  are the authenticity markers.

### Screenshot #2 — Gitleaks detection

- In the `scan` job, expand the **`Gitleaks secret scan (Gate 0)`** step.
- Capture the finding lines. Gitleaks reports the rule id (e.g.
  `aws-access-token`, `acr-demo-db-password`), the file
  (`fixtures/vuln_secret.py`), and the commit/line.
- If your repo shows a **job summary** panel (Gitleaks writes one when
  `GITLEAKS_ENABLE_SUMMARY=true`), capture that too — it's a cleaner figure.
- **Reference:** the finding should point at `fixtures/vuln_secret.py`. The
  local G0 gate detects the same secret; see `docs/reference_output` note below.

### Screenshot #3 — Semgrep / Bandit results

- Expand the **`Semgrep SAST (Gate 1a)`** step. Capture the grouped
  "Semgrep findings" block. Expected: `acr-sql-string-concat @
  fixtures/vuln_sqli.py:13`.
- Expand the **`Bandit SAST (Gate 1b)`** step. Capture the "Bandit findings"
  block. Expected: `B608 MEDIUM @ vuln_sqli.py:12` and `B105 LOW @
  vuln_secret.py` (hardcoded password).
- You can put both in one screenshot (scroll so both step headers show) or
  capture them as 3a and 3b.
- **Reference files:** `docs/reference_output/semgrep.json`,
  `docs/reference_output/bandit.json` — your run should list the same rule ids.

### Screenshot #4 — Claude JSON response

- Expand the **`Claude constrained review (Gate 3)`** step.
- Capture the `Backend: anthropic` (or `mock`) line **and** the JSON object that
  follows. The JSON is the model's structured finding for the IDOR fixture:
  a `findings` array with `rule_id`, `severity`, `cwe` (CWE-639),
  `confidence`, and `rationale`.
- **Reference:** `docs/reference_output/claude_response.json` shows the exact
  shape (the mock output; the real model's wording will differ but the schema is
  identical, because Gate 3 enforces the JSON contract).

### Screenshot #5 — GitHub Environment approval

- Because the scan escalated, the **`Human-in-the-loop approval (Gate 5)`** job
  is paused with a yellow **"Waiting"** state and a **"Review pending
  deployments"** button.
- Click **Review pending deployments** → tick `security-review` → the approval
  dialog appears with an optional comment box and **Approve and deploy** /
  **Reject** buttons. **Capture this dialog** — it is the human-in-the-loop
  approval screen.
- (Optional 5b) After approving, capture the now-green approval job showing the
  reviewer name and the "approved" event — this demonstrates the audit trail.

---

## Part D — Verify before you screenshot (recommended)

Run the prototype locally first so you know exactly what each step should show.
From the project root:

```bash
pip install -r requirements.txt
export PYTHONPATH=.

# #4 Claude JSON (mock, offline) — matches docs/reference_output/claude_response.json
python scripts/claude_review_demo.py fixtures/vuln_idor.py

# #3 Semgrep + Bandit
semgrep scan --config rulesets/semgrep-acr.yml fixtures/
bandit -r fixtures/

# #1/#5 full pipeline decision (ESCALATE -> exit 1 -> approval gate)
python -m hybrid_acr.cli scan fixtures/vuln_idor.py --ledger audit/ledger.jsonl
echo "exit code: $?"   # 1 = ESCALATE
```

The `docs/reference_output/` folder contains a captured copy of each of these
outputs from a known-good local run, so you can diff your results against it.

---

## Part E — Honesty notes for the write-up

Two things worth stating plainly in the appendix or methodology, because a viva
panel may ask:

1. **The credentials in the fixtures are fake.** They exist only to exercise the
   secret scanner. Say so once; it pre-empts the obvious question and shows good
   practice. The fixture header and `.gitleaks.toml` comment both record this.

2. **If the Claude step used the mock backend** (no API key), state that the
   figure shows the enforced JSON *contract* rather than a live model inference,
   and that the contract is identical either way because Gate 3 validates the
   output schema. If you used the real key, note the model id (e.g.
   `claude-sonnet-4-6`) visible in the step log — that is the honest, checkable
   detail.

Doing it this way means every figure in Appendix I is a real capture you can
defend, with reconcilable run metadata, rather than an illustration.
