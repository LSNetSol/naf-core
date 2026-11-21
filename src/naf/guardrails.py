"""M4: Zero Trust guardrails: short-lived scoped credentials and dual approval.

Tokens here are HMAC-signed for demonstration. Production deployments should issue credentials from
an identity provider or a secrets manager and never keep standing admin access (NIST SP 800-207).
"""
from __future__ import annotations
import hashlib, hmac, json, time
from typing import Iterable, Optional


def _sig(key: bytes, body: dict) -> str:
    return hmac.new(key, json.dumps(body, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()


def issue_token(key: bytes, subject: str, device: str, action: str, ttl_s: int = 300, now: Optional[float] = None) -> dict:
    now = time.time() if now is None else now
    body = {"sub": subject, "device": device, "action": action, "exp": int(now + ttl_s)}
    return {**body, "sig": _sig(key, body)}


def verify_token(key: bytes, token: dict, device: str, action: str, now: Optional[float] = None) -> bool:
    now = time.time() if now is None else now
    body = {k: token.get(k) for k in ("sub", "device", "action", "exp")}
    return (hmac.compare_digest(token.get("sig", ""), _sig(key, body)) and token.get("device") == device
            and token.get("action") == action and now < token.get("exp", 0))


def dual_approval(approvals: Iterable[dict], requester: str, required: int = 2) -> bool:
    """True if at least ``required`` distinct approvers other than the requester approved."""
    approvers = {a["approver"] for a in approvals if a.get("approved") and a.get("approver") != requester}
    return len(approvers) >= required
