"""Append-only, hash-chained evidence log (JSON lines).

Each record stores the SHA-256 of the previous record, so any later modification or deletion
breaks the chain. This is a tamper-*evident* log; production deployments should also sign the
head of the chain and replicate it off-box (see the threat model).
"""
from __future__ import annotations

import hashlib
import json
from typing import List

GENESIS = "0" * 64


def _digest(prev: str, body: dict) -> str:
    payload = json.dumps({"prev": prev, "body": body}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


class EvidenceLog:
    def __init__(self, path: str):
        self.path = path

    def _records(self) -> List[dict]:
        try:
            with open(self.path, encoding="utf-8") as fh:
                return [json.loads(line) for line in fh if line.strip()]
        except FileNotFoundError:
            return []

    def append(self, body: dict) -> dict:
        records = self._records()
        prev = records[-1]["hash"] if records else GENESIS
        rec = {"prev": prev, "body": body, "hash": _digest(prev, body)}
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
        return rec

    def verify(self) -> bool:
        prev = GENESIS
        for rec in self._records():
            if rec["prev"] != prev or rec["hash"] != _digest(prev, rec["body"]):
                return False
            prev = rec["hash"]
        return True
