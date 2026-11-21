import json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from naf.evidence import EvidenceLog
from naf.detectors import detect
from naf.rpki import VRP

VRPS = [VRP("192.0.2.0/24", 24, 64496)]
REL = {(64500, 64496): "p2c", (64500, 64501): "p2p", (64502, 64500): "c2p", (64501, 64502): "c2p"}


class TestEvidence(unittest.TestCase):
    def test_chain_verifies_and_detects_tampering(self):
        path = os.path.join(tempfile.mkdtemp(), "e.jsonl")
        log = EvidenceLog(path)
        log.append({"stage": "incident"})
        log.append({"stage": "gate", "allowed": False})
        self.assertTrue(log.verify())
        lines = open(path).read().splitlines()
        rec = json.loads(lines[0]); rec["body"]["stage"] = "edited"
        lines[0] = json.dumps(rec, sort_keys=True)
        open(path, "w").write("\n".join(lines) + "\n")
        self.assertFalse(EvidenceLog(path).verify())


class TestDetectors(unittest.TestCase):
    def test_hijack_detected_on_invalid_origin(self):
        inc = detect({"prefix": "192.0.2.0/24", "as_path": [64502, 64511]}, VRPS, REL)
        self.assertEqual([i["type"] for i in inc], ["prefix_hijack"])

    def test_clean_route_has_no_incident(self):
        inc = detect({"prefix": "192.0.2.0/24", "as_path": [64500, 64496]}, VRPS, REL)
        self.assertEqual(inc, [])


if __name__ == "__main__":
    unittest.main()
