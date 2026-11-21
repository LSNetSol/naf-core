"""RPKI route origin validation (RFC 6811).

A route (prefix, origin AS) is evaluated against Validated ROA Payloads (VRPs):

* ``valid``      a VRP covers the prefix, matches the origin AS and the prefix length
                 is <= the VRP maxLength;
* ``invalid``    at least one VRP covers the prefix but none matches both origin AS and length;
* ``not_found``  no VRP covers the prefix.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable

VALID, INVALID, NOT_FOUND = "valid", "invalid", "not_found"


@dataclass(frozen=True)
class VRP:
    prefix: str
    max_length: int
    asn: int

    def network(self):
        return ipaddress.ip_network(self.prefix, strict=True)


def validate(prefix: str, origin_asn: int, vrps: Iterable[VRP]) -> str:
    """Return ``valid``, ``invalid`` or ``not_found`` for a route (RFC 6811, section 2)."""
    route = ipaddress.ip_network(prefix, strict=True)
    covered = False
    for vrp in vrps:
        net = vrp.network()
        if net.version != route.version:
            continue
        if route.subnet_of(net):  # the VRP prefix covers the route prefix
            covered = True
            if vrp.asn == origin_asn and route.prefixlen <= vrp.max_length:
                return VALID
    return INVALID if covered else NOT_FOUND
