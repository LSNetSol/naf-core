import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from naf.verify import check_change
from naf.remediate import execute, FakeDriver
from naf.policy import Decision
from naf.guardrails import issue_token, verify_token, dual_approval
from naf.report import build_incident_record, export_json

INTENT = {"protected_prefixes": ["192.0.2.0/24"], "max_ops": 3}


class TestVerify(unittest.TestCase):
    def good(self):
        return {"device": "edge-a", "snapshot": True, "ops": [{"op": "apply_prefix_filter", "prefix": "198.51.100.0/24"}]}

    def test_good_change_passes(self):
        self.assertEqual(check_change(self.good(), INTENT), [])

    def test_blocks_protected_withdrawal(self):
        c = self.good(); c["ops"] = [{"op": "withdraw_prefix", "prefix": "192.0.2.0/24"}]
        self.assertTrue(any("protected" in v for v in check_change(c, INTENT)))

    def test_blocks_unknown_op_missing_snapshot_and_too_many(self):
        c = {"device": "edge-a", "ops": [{"op": "reboot"}] * 4}
        v = check_change(c, INTENT)
        self.assertTrue(any("unknown operation" in x for x in v))
        self.assertTrue(any("no snapshot" in x for x in v))
        self.assertTrue(any("exceed limit" in x for x in v))


class TestRemediate(unittest.TestCase):
    def test_denied_does_nothing(self):
        d = FakeDriver()
        r = execute(Decision(False, "approval required"), "edge-a", [{"op": "x"}], d, lambda: True)
        self.assertEqual(r["status"], "denied"); self.assertEqual(d.state, {})

    def test_success(self):
        d = FakeDriver(); log = []
        r = execute(Decision(True, "ok"), "edge-a", [{"op": "x"}], d, lambda: True, log)
        self.assertEqual(r["status"], "done"); self.assertEqual(log[-1]["stage"], "verified")

    def test_verification_failure_rolls_back(self):
        d = FakeDriver(); d.state["edge-a"] = {"applied": ["old"]}
        r = execute(Decision(True, "ok"), "edge-a", [{"op": "new"}], d, lambda: False)
        self.assertEqual(r["status"], "rolled_back"); self.assertEqual(d.state["edge-a"], {"applied": ["old"]})

    def test_apply_error_rolls_back(self):
        d = FakeDriver(fail_apply=True)
        r = execute(Decision(True, "ok"), "edge-a", [{"op": "new"}], d, lambda: True)
        self.assertEqual(r["status"], "rolled_back")


class TestGuardrails(unittest.TestCase):
    K = b"k"

    def test_token_valid_then_expired(self):
        t = issue_token(self.K, "automation", "edge-a", "apply_filter", ttl_s=60, now=1000)
        self.assertTrue(verify_token(self.K, t, "edge-a", "apply_filter", now=1030))
        self.assertFalse(verify_token(self.K, t, "edge-a", "apply_filter", now=1100))

    def test_token_scope_and_tamper(self):
        t = issue_token(self.K, "automation", "edge-a", "apply_filter", now=1000)
        self.assertFalse(verify_token(self.K, t, "edge-b", "apply_filter", now=1001))
        t["device"] = "edge-b"
        self.assertFalse(verify_token(self.K, t, "edge-b", "apply_filter", now=1001))

    def test_dual_approval(self):
        a = [{"approver": "a", "approved": True}, {"approver": "b", "approved": True}]
        self.assertTrue(dual_approval(a, requester="r"))
        self.assertFalse(dual_approval(a[:1], requester="r"))
        self.assertFalse(dual_approval([{"approver": "r", "approved": True}, {"approver": "a", "approved": True}], requester="r"))


class TestReport(unittest.TestCase):
    def test_record(self):
        rec = build_incident_record({"type": "route_leak", "prefix": "192.0.2.0/24"}, "abc",
                                    [{"stage": "applied", "device": "edge-a"}, {"stage": "verified"}], 1700000000)
        self.assertEqual(rec["status"], "closed")
        self.assertIn("route_leak", export_json(rec))


if __name__ == "__main__":
    unittest.main()
