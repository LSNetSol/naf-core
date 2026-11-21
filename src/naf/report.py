"""Incident record export. Fields follow what incident-reporting regimes typically ask for.

CIRCIA's final rule is not yet published (sent to OMB Oct 1, 2026), so these fields are a configurable
template, not a claim of compliance with a final rule.
"""
from __future__ import annotations
import json
from typing import List

FIELDS = ("incident_id", "type", "detected_at", "affected_prefixes", "affected_devices",
          "actions_taken", "status", "evidence_head")


def build_incident_record(incident: dict, evidence_head: str, actions: List[dict], detected_at: int) -> dict:
    return {
        "incident_id": f"inc-{detected_at}-{incident['type']}",
        "type": incident["type"],
        "detected_at": detected_at,
        "affected_prefixes": [incident["prefix"]] if "prefix" in incident else [],
        "affected_devices": sorted({a.get("device") for a in actions if a.get("device")}),
        "actions_taken": actions,
        "status": "closed" if actions and actions[-1].get("stage") in ("verified",) else "open",
        "evidence_head": evidence_head,
    }


def export_json(record: dict) -> str:
    return json.dumps({k: record.get(k) for k in FIELDS}, indent=2, sort_keys=True)
