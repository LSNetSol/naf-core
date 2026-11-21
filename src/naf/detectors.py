"""Detectors: turn BGP update events into incidents (never into actions)."""
from __future__ import annotations

from typing import Dict, Iterable, List

from .leak import Relationships, check_as_path
from .rpki import INVALID, VRP, validate


def detect(event: dict, vrps: Iterable[VRP], rel: Relationships, expected_origins: Dict[str, int] | None = None) -> List[dict]:
    """Evaluate one BGP update event.

    ``event`` has ``prefix`` and ``as_path`` (nearest AS first, origin last).
    Returns a list of incident dictionaries (possibly empty).
    """
    incidents: List[dict] = []
    prefix = event["prefix"]
    as_path = event["as_path"]
    origin = as_path[-1]

    status = validate(prefix, origin, list(vrps))
    expected = (expected_origins or {}).get(prefix)
    if status == INVALID or (expected is not None and expected != origin):
        incidents.append({
            "type": "prefix_hijack",
            "prefix": prefix,
            "origin": origin,
            "rpki": status,
            "evidence": {"as_path": as_path, "expected_origin": expected},
        })

    verdict = check_as_path(as_path, rel)
    if verdict["verdict"] == "leak":
        incidents.append({
            "type": "route_leak",
            "prefix": prefix,
            "origin": origin,
            "evidence": {"as_path": as_path, **verdict},
        })
    return incidents
