"""Print the raw Claude (Gate 3) JSON contract response for a target file.

Used by the Appendix I workflow to capture screenshot #4 (Claude JSON response).
Honours ACR_LLM_BACKEND: 'anthropic' (real API, needs ANTHROPIC_API_KEY) or
'mock' (deterministic, offline). Prints the exact JSON the model returned, plus
a one-line provenance banner to stderr so the screenshot records which backend
produced it.

Usage:  python scripts/claude_review_demo.py <path-to-file.py>
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hybrid_acr.llm_backend import get_backend


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: claude_review_demo.py <file>", file=sys.stderr)
        return 2
    path = sys.argv[1]
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        code = fh.read()

    backend = get_backend()
    print(f"[provenance] backend={backend.name} file={path}", file=sys.stderr)

    raw = backend.review(code, sast_summary="(fed from Gate 1 in full pipeline)")

    # Pretty-print if it parses, else emit raw (the gate would ESCALATE on
    # non-JSON; here we show exactly what came back).
    try:
        obj = json.loads(raw)
        print(json.dumps(obj, indent=2))
    except json.JSONDecodeError:
        print(raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
