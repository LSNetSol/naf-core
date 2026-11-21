"""Layer 2: normalized event schema shared by all collectors and detectors."""
from __future__ import annotations
from typing import List

REQUIRED = ("ts", "source", "kind")


def validate_event(ev: dict) -> dict:
    missing = [k for k in REQUIRED if k not in ev]
    if missing:
        raise ValueError(f"event missing fields: {missing}")
    return ev


def bgp_update_event(ts: int, peer_as: int, prefix: str, as_path: List[int]) -> dict:
    """Normalized BGP update event, as consumed by naf.detectors.detect."""
    return validate_event({"ts": ts, "source": "bmp", "kind": "bgp_update",
                           "peer_as": peer_as, "prefix": prefix, "as_path": list(as_path)})
