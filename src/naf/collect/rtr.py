"""RPKI-to-Router protocol (RFC 8210): IPv4 Prefix PDU parser producing VRPs."""
from __future__ import annotations
import ipaddress, struct
from ..rpki import VRP

IPV4_PREFIX_PDU = 4


def parse_ipv4_prefix_pdu(data: bytes):
    """Return (announce: bool, VRP) from a 20-byte IPv4 Prefix PDU."""
    if len(data) != 20:
        raise ValueError("IPv4 Prefix PDU must be 20 bytes")
    version, ptype, _zero, length = struct.unpack("!BBHI", data[:8])
    if ptype != IPV4_PREFIX_PDU or length != 20:
        raise ValueError("not an IPv4 Prefix PDU")
    flags, plen, maxlen, _ = struct.unpack("!BBBB", data[8:12])
    prefix = ipaddress.IPv4Address(data[12:16])
    asn, = struct.unpack("!I", data[16:20])
    return bool(flags & 1), VRP(f"{prefix}/{plen}", maxlen, asn)
