"""Route-leak check based on the valley-free (Gao-Rexford) model.

Relationships are given as a mapping ``(a, b) -> "p2c" | "c2p" | "p2p"`` meaning, from the
point of view of AS ``a``, that ``b`` is its customer (p2c), provider (c2p) or peer (p2p).

A route propagating from the origin towards the observer is valley-free if it has the form
``up* [peer] down*``: any number of customer-to-provider steps, at most one peer step, then any
number of provider-to-customer steps. Anything else (for example, a route learned from a
provider or peer and then exported to another provider or peer) is a leak candidate.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

Relationships = Dict[Tuple[int, int], str]


def _step(a: int, b: int, rel: Relationships) -> Optional[str]:
    """Direction of the propagation step a -> b: ``up``, ``peer`` or ``down`` (None if unknown)."""
    r = rel.get((a, b))
    if r is None:
        inv = rel.get((b, a))
        r = {"p2c": "c2p", "c2p": "p2c", "p2p": "p2p"}.get(inv) if inv else None
    return {"c2p": "up", "p2p": "peer", "p2c": "down"}.get(r) if r else None


def check_as_path(as_path: List[int], rel: Relationships) -> dict:
    """Check an AS path as seen in a BGP UPDATE (nearest AS first, origin AS last).

    Returns ``{"verdict": "ok" | "leak" | "unverifiable", "index": int | None, "reason": str}``.
    ``index`` is the position, in the origin-to-observer order, of the first offending hop.
    """
    # collapse prepending
    path: List[int] = []
    for asn in as_path:
        if not path or path[-1] != asn:
            path.append(asn)
    propagation = list(reversed(path))  # origin -> ... -> neighbor
    state = "up"  # allowed to go up/peer/down
    unknown = False
    for i in range(len(propagation) - 1):
        d = _step(propagation[i], propagation[i + 1], rel)
        if d is None:
            unknown = True
            continue
        if state == "up":
            if d == "peer":
                state = "after_peer"
            elif d == "down":
                state = "down"
        else:  # after a peer or down step only down steps are allowed
            if d in ("up", "peer"):
                return {
                    "verdict": "leak",
                    "index": i,
                    "reason": f"AS{propagation[i]} -> AS{propagation[i + 1]} is a {d} step after a "
                              f"{'peer' if state == 'after_peer' else 'down'} step (valley)",
                }
    if unknown:
        return {"verdict": "unverifiable", "index": None, "reason": "missing relationship data"}
    return {"verdict": "ok", "index": None, "reason": "valley-free"}
