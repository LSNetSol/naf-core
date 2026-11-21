"""Policy gate: the only component allowed to approve an action.

A runbook is a declarative document (see ``examples/runbooks/filter_leaked_prefix.json``).
The gate evaluates the same checks, in the same order, for every proposed action:

1. runbook is signed by the approved key;
2. incident type matches the runbook trigger;
3. target devices are inside the declared scope and the change is under the impact cap;
4. autonomy level is high enough to run without approval, or a recorded approval is present;
5. a snapshot step and a rollback are defined;
6. (after execution, outside this module) verification must pass, otherwise roll back.

The signature here is an HMAC for demonstration only. A real deployment uses asymmetric
signatures (for example, signed Git commits) and short-lived device credentials.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import List, Optional

OBSERVE, APPROVE, ACT_NOTIFY, ACT_LIMITS = 0, 1, 2, 3


def sign(runbook: dict, key: bytes) -> str:
    body = {k: v for k, v in runbook.items() if k != "signature"}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key, canon, hashlib.sha256).hexdigest()


@dataclass
class Decision:
    allowed: bool
    reason: str
    needs_approval: bool = False

    def __bool__(self):
        return self.allowed


def evaluate(runbook: dict, incident: dict, targets: List[str], prefix_count: int, key: bytes,
             operator_level: int, approval: Optional[dict] = None) -> Decision:
    """Evaluate a proposed action. ``operator_level`` is the level the operator enabled."""
    # 1. signature
    if not hmac.compare_digest(runbook.get("signature", ""), sign(runbook, key)):
        return Decision(False, "runbook signature invalid")
    # 2. trigger
    if incident.get("type") != runbook.get("trigger"):
        return Decision(False, "incident type does not match runbook trigger")
    # 3. scope and impact cap
    scope = runbook.get("scope", {})
    if not set(targets) <= set(scope.get("devices", [])):
        return Decision(False, "target outside declared device scope")
    if prefix_count > scope.get("max_prefixes", 0):
        return Decision(False, "change exceeds impact cap")
    # 5. snapshot and rollback must exist before any change
    steps = runbook.get("steps", [])
    if "snapshot_config" not in steps or not runbook.get("rollback"):
        return Decision(False, "no snapshot step or rollback defined")
    # 4. autonomy and approval
    level = min(runbook.get("autonomy_level", OBSERVE), operator_level)
    if level == OBSERVE:
        return Decision(False, "observe-only: recommend, do not act")
    needs = level == APPROVE or runbook.get("approval") == "required"
    if needs and not (approval and approval.get("approved") is True and approval.get("approver")):
        return Decision(False, "approval required and not present", needs_approval=True)
    return Decision(True, "allowed")
