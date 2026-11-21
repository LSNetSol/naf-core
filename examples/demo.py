"""Replay a synthetic route leak end to end: detect -> propose -> gate -> evidence."""
import json, os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from naf.rpki import VRP
from naf.detectors import detect
from naf.policy import evaluate, sign
from naf.evidence import EvidenceLog

here = os.path.dirname(__file__)
vrps = [VRP(**v) for v in json.load(open(os.path.join(here, "data", "vrps_sample.json")))]
raw = json.load(open(os.path.join(here, "data", "relationships_sample.json")))["relationships"]
rel = {tuple(int(x) for x in k.split(",")): v for k, v in raw.items()}
key = b"demo-key-not-for-production"

runbook = json.load(open(os.path.join(here, "runbooks", "filter_leaked_prefix.json")))
runbook["signature"] = sign(runbook, key)

# AS64501 (a peer of 64500) re-announces a route it learned from its peer 64500 to provider 64502: a leak.
event = {"prefix": "192.0.2.0/24", "as_path": [64502, 64501, 64500, 64496]}
log = EvidenceLog(os.path.join(tempfile.mkdtemp(), "evidence.jsonl"))

for inc in detect(event, vrps, rel):
    log.append({"stage": "incident", **inc})
    print("INCIDENT:", inc["type"], inc.get("evidence", {}).get("reason", ""))
    if inc["type"] != runbook["trigger"]:
        continue
    d1 = evaluate(runbook, inc, ["edge-a"], 1, key, operator_level=1)
    print("GATE (no approval):", d1.allowed, "-", d1.reason)
    log.append({"stage": "gate", "allowed": d1.allowed, "reason": d1.reason})
    d2 = evaluate(runbook, inc, ["edge-a"], 1, key, operator_level=1, approval={"approved": True, "approver": "operator-1"})
    print("GATE (approved):  ", d2.allowed, "-", d2.reason)
    log.append({"stage": "gate", "allowed": d2.allowed, "reason": d2.reason, "approver": "operator-1"})
print("Evidence chain intact:", log.verify())
