"""gNMI collector interface and a parser for gNMI-style notifications (live subscribe is planned for v0.5)."""
from __future__ import annotations
from typing import Iterable, List


def parse_notification(notification: dict) -> List[dict]:
    """Turn a gNMI-style notification dict into normalized events.

    Input shape (as JSON-encoded by common gNMI tools):
    {"timestamp": 1700000000000000000, "prefix": "interfaces/interface[name=eth1]",
     "update": [{"path": "state/oper-status", "val": "DOWN"}]}
    """
    ts = int(notification["timestamp"]) // 1_000_000_000
    prefix = notification.get("prefix", "").strip("/")
    out = []
    for up in notification.get("update", []):
        path = "/".join(p for p in (prefix, up["path"].strip("/")) if p)
        out.append({"ts": ts, "source": "gnmi", "kind": "state", "path": path, "value": up["val"]})
    return out


class GnmiCollector:
    """Interface only. A real collector opens a TLS gNMI Subscribe stream (TCP 9339) per device."""

    def __init__(self, targets: Iterable[str]):
        self.targets = list(targets)

    def run(self):  # pragma: no cover
        raise NotImplementedError("live gNMI subscribe is planned for v0.5")
