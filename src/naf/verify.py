"""M1: pre-change verification. A proposed change is a dict; rules return violations.

Change format: {"device": "edge-a", "ops": [{"op": "withdraw_prefix", "prefix": "192.0.2.0/24"}, ...],
                "snapshot": true, "window": "2026-12-01T02:00Z"}
Intent format: {"protected_prefixes": [...], "max_ops": 20, "allowed_ops": [...]}
Every rule is deterministic and testable; a change with any violation is blocked.
"""
from __future__ import annotations
from typing import List

ALLOWED_OPS = {"set_interface", "set_bgp_neighbor", "apply_prefix_filter", "withdraw_prefix",
               "announce_prefix", "set_route_policy"}


def check_change(change: dict, intent: dict) -> List[str]:
    violations: List[str] = []
    ops = change.get("ops", [])
    allowed = set(intent.get("allowed_ops", ALLOWED_OPS))
    protected = set(intent.get("protected_prefixes", []))
    if not change.get("device"):
        violations.append("syntax: missing device")
    if not change.get("snapshot"):
        violations.append("policy: no snapshot requested before change")
    if len(ops) > intent.get("max_ops", 20):
        violations.append(f"policy: {len(ops)} operations exceed limit")
    for i, op in enumerate(ops):
        name = op.get("op")
        if name not in ALLOWED_OPS:
            violations.append(f"syntax: unknown operation '{name}' at {i}")
        elif name not in allowed:
            violations.append(f"policy: operation '{name}' not allowed at {i}")
        if name == "withdraw_prefix" and op.get("prefix") in protected:
            violations.append(f"reachability: withdraws protected prefix {op.get('prefix')}")
    return violations
