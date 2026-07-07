"""Command-line interface for the Hybrid-Secure-ACR pipeline.

Usage:
    python -m hybrid_acr.cli scan <path> [--config hybrid|sast-only|llm-augmented]
                                         [--sensitive] [--pr-text "..."]
                                         [--ledger audit/ledger.jsonl]
                                         [--json] [--confidence-floor 0.5]
    python -m hybrid_acr.cli verify-ledger <path>

Exit codes (so CI can gate on them):
    0  PASS
    1  ESCALATE  (human review required)
    2  BLOCK     (hard stop)
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .audit import AuditLedger
from .models import Decision, ReviewContext
from .pipeline import HybridACRPipeline


EXIT_CODES = {Decision.PASS: 0, Decision.ESCALATE: 1, Decision.BLOCK: 2, Decision.ABORT: 2}

# Path fragments that mark a change as sensitive (RTA Theme 6: P07's /crypto/,
# /pci/ CODEOWNERS rule). Auto-detected unless --sensitive is forced.
SENSITIVE_FRAGMENTS = ("crypto", "/pci", "auth", "payment", "secret", "/key")


def _collect_files(path: str) -> list[str]:
    if os.path.isfile(path):
        return [path]
    out = []
    for root, _dirs, names in os.walk(path):
        if any(skip in root for skip in (".git", "__pycache__", "node_modules", ".venv")):
            continue
        for n in names:
            if n.endswith((".py", ".js", ".ts", ".java", ".go", ".rb", ".php")):
                out.append(os.path.join(root, n))
    return out


def cmd_scan(args: argparse.Namespace) -> int:
    files = _collect_files(args.path)
    if not files:
        print(f"No source files found under {args.path}", file=sys.stderr)
        return 0

    sensitive = args.sensitive or any(
        frag in args.path.lower() or any(frag in f.lower() for f in files)
        for frag in SENSITIVE_FRAGMENTS
    )

    ctx = ReviewContext(
        target_path=args.path, files=files,
        untrusted_text=args.pr_text or "", sensitive=sensitive,
    )
    ledger = AuditLedger(args.ledger)
    pipeline = HybridACRPipeline(ledger, config=args.config,
                                 confidence_floor=args.confidence_floor)
    result = pipeline.run(ctx)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_human(result)
    return EXIT_CODES.get(result.decision, 0)


def _print_human(result) -> None:
    bar = "=" * 64
    print(bar)
    print(f" Hybrid-Secure-ACR  |  config={result.config}  |  run={result.run_id}")
    print(bar)
    for gr in result.gate_results:
        flag = "  [ABORTED PIPELINE]" if gr.aborted_pipeline else ""
        print(f" {gr.gate_id} {gr.gate_name:<28} -> {gr.decision.value}{flag}")
        for f in gr.findings:
            tag = "verified" if f.verified else "UNVERIFIED"
            print(f"      - [{f.severity.name:<8}] {f.cwe or '-':<9} {f.title}  ({tag})")
    print(bar)
    s = result.summary()
    print(f" Findings: {s['total_findings']}  by source: {s['findings_by_source']}")
    print(f" Max severity: {s['max_severity']}")
    if result.aborted_at:
        print(f" Pipeline halted at: {result.aborted_at}")
    print(f" FINAL DECISION: {result.decision.value}")
    print(bar)


def cmd_verify(args: argparse.Namespace) -> int:
    ledger = AuditLedger(args.path)
    ok = ledger.verify_chain()
    print(f"Ledger chain integrity: {'OK (tamper-evident, intact)' if ok else 'BROKEN'}")
    print(f"Entries: {len(ledger.entries())}")
    return 0 if ok else 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hybrid-acr",
                                description="Hybrid AI-Human Security Framework for LLM-based ACR")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Run the pipeline over a path")
    s.add_argument("path")
    s.add_argument("--config", choices=["hybrid", "sast-only", "llm-augmented"],
                   default="hybrid")
    s.add_argument("--sensitive", action="store_true",
                   help="Force sensitive-path routing (stricter HITL).")
    s.add_argument("--pr-text", default="",
                   help="Untrusted PR/commit text to screen for injection (G2).")
    s.add_argument("--ledger", default="audit/ledger.jsonl")
    s.add_argument("--confidence-floor", type=float, default=0.5)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_scan)

    v = sub.add_parser("verify-ledger", help="Verify audit ledger hash chain")
    v.add_argument("path")
    v.set_defaults(func=cmd_verify)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
