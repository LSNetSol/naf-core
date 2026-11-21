"""M3: closed-loop remediation executor. Acts only after the policy gate allows the action.

Sequence: gate -> snapshot -> apply -> verify -> (rollback on any failure). The device driver is an
interface; v0.2 ships an in-memory FakeDriver used by tests and the demo. Real NETCONF/gNMI drivers
are planned for v1.0.
"""
from __future__ import annotations
from typing import Callable, List, Protocol

from .policy import Decision


class Driver(Protocol):
    def snapshot(self, device: str) -> str: ...
    def apply(self, device: str, steps: List[dict]) -> None: ...
    def restore(self, device: str, snapshot_id: str) -> None: ...


class FakeDriver:
    def __init__(self, fail_apply: bool = False):
        self.state = {}
        self.snaps = {}
        self.fail_apply = fail_apply

    def snapshot(self, device):
        sid = f"snap-{len(self.snaps) + 1}"
        self.snaps[sid] = dict(self.state.get(device, {}))
        return sid

    def apply(self, device, steps):
        if self.fail_apply:
            raise RuntimeError("apply failed")
        self.state.setdefault(device, {})["applied"] = list(steps)

    def restore(self, device, snapshot_id):
        self.state[device] = dict(self.snaps[snapshot_id])


def execute(decision: Decision, device: str, steps: List[dict], driver: Driver,
            verify: Callable[[], bool], log=None) -> dict:
    """Run a remediation. Returns {"status": "done" | "rolled_back" | "denied", ...}."""
    def rec(**kw):
        if log is not None:
            log.append(kw)
    if not decision:
        rec(stage="denied", reason=decision.reason)
        return {"status": "denied", "reason": decision.reason}
    sid = driver.snapshot(device)
    rec(stage="snapshot", id=sid)
    try:
        driver.apply(device, steps)
        rec(stage="applied", steps=len(steps))
        ok = verify()
    except Exception as exc:  # any failure triggers rollback
        rec(stage="error", error=str(exc))
        ok = False
    if ok:
        rec(stage="verified")
        return {"status": "done", "snapshot": sid}
    driver.restore(device, sid)
    rec(stage="rolled_back", id=sid)
    return {"status": "rolled_back", "snapshot": sid}
