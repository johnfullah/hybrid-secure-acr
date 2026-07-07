"""Immutable audit ledger.

RTA Theme 5 (Governance Vacuum) identified audit-trail inadequacy as the single
most consistently reported governance gap (16/16 participants). P01's
specification of an "audit-ready trail" required: immutable log of system prompt
+ user input + model output + human override reason + timestamp + reviewer
identity. P13 added attestation of due-diligence review and logged escalation
triggers.

This module implements that as a hash-chained append-only ledger (each entry
embeds the SHA-256 of the previous entry, so any tampering is detectable). It is
NOT a production-grade immutable store -- a real deployment would push these
records to a WORM bucket or append-only log service -- but it operationalises
the *shape* of the requirement so the prototype can be evaluated against it.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any


GENESIS_HASH = "0" * 64


class AuditLedger:
    def __init__(self, path: str) -> None:
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        if not os.path.exists(path):
            open(path, "a").close()

    def _last_hash(self) -> str:
        last = GENESIS_HASH
        if os.path.getsize(self.path) == 0:
            return last
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = json.loads(line)["entry_hash"]
        return last

    @staticmethod
    def _hash_entry(payload: dict[str, Any], prev_hash: str) -> str:
        # Deterministic serialisation so the hash is reproducible.
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()

    def append(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        prev = self._last_hash()
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "payload": payload,
            "prev_hash": prev,
        }
        record["entry_hash"] = self._hash_entry(
            {"ts": record["ts"], "event_type": event_type, "payload": payload}, prev
        )
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
        return record

    def verify_chain(self) -> bool:
        """Re-walk the chain and confirm no entry was altered or removed."""
        prev = GENESIS_HASH
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if rec["prev_hash"] != prev:
                    return False
                expected = self._hash_entry(
                    {"ts": rec["ts"], "event_type": rec["event_type"],
                     "payload": rec["payload"]},
                    prev,
                )
                if expected != rec["entry_hash"]:
                    return False
                prev = rec["entry_hash"]
        return True

    def entries(self) -> list[dict[str, Any]]:
        out = []
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out
