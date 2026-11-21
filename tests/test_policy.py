import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from naf.policy import evaluate, sign

KEY = b"test-key"


def runbook(**over):
    rb = {
        "name": "filter-leaked-prefix", "trigger": "route_leak", "autonomy_level": 1,
        "scope": {"devices": ["edge-a", "edge-b"], "max_prefixes": 5},
        "steps": ["snapshot_config", "apply_prefix_filter", "verify:bgp_state_matches_intent"],
        "rollback": "restore_snapshot", "approval": "required", "expires_after": "4h",
    }
    rb.update(over)
    rb["signature"] = sign(rb, KEY)
    return rb


INC = {"type": "route_leak"}
OK_APPROVAL = {"approved": True, "approver": "op-1"}


class TestGate(unittest.TestCase):
    def test_allowed_with_approval(self):
        self.assertTrue(evaluate(runbook(), INC, ["edge-a"], 2, KEY, 1, OK_APPROVAL))

    def test_blocked_without_approval(self):
        d = evaluate(runbook(), INC, ["edge-a"], 2, KEY, 1)
        self.assertFalse(d)
        self.assertTrue(d.needs_approval)

    def test_tampered_runbook_rejected(self):
        rb = runbook()
        rb["scope"]["max_prefixes"] = 500  # changed after signing
        self.assertFalse(evaluate(rb, INC, ["edge-a"], 2, KEY, 1, OK_APPROVAL))

    def test_wrong_trigger_rejected(self):
        self.assertFalse(evaluate(runbook(), {"type": "ddos"}, ["edge-a"], 2, KEY, 1, OK_APPROVAL))

    def test_out_of_scope_device_rejected(self):
        self.assertFalse(evaluate(runbook(), INC, ["core-1"], 2, KEY, 1, OK_APPROVAL))

    def test_impact_cap_enforced(self):
        self.assertFalse(evaluate(runbook(), INC, ["edge-a"], 6, KEY, 1, OK_APPROVAL))

    def test_observe_only_never_acts(self):
        self.assertFalse(evaluate(runbook(), INC, ["edge-a"], 2, KEY, 0, OK_APPROVAL))

    def test_no_rollback_rejected(self):
        self.assertFalse(evaluate(runbook(rollback=""), INC, ["edge-a"], 2, KEY, 1, OK_APPROVAL))

    def test_operator_level_caps_runbook_level(self):
        rb = runbook(autonomy_level=3, approval="none")
        self.assertFalse(evaluate(rb, INC, ["edge-a"], 2, KEY, 0))


if __name__ == "__main__":
    unittest.main()
