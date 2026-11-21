"""BGP Monitoring Protocol (RFC 7854): common header and per-peer header parsers."""
from __future__ import annotations
import ipaddress, struct
from dataclasses import dataclass

MSG_TYPES = {0: "route_monitoring", 1: "stats_report", 2: "peer_down", 3: "peer_up",
             4: "initiation", 5: "termination", 6: "route_mirroring"}


@dataclass(frozen=True)
class CommonHeader:
    version: int
    length: int
    msg_type: str


@dataclass(frozen=True)
class PerPeerHeader:
    peer_type: int
    flags: int
    peer_address: str
    peer_as: int
    bgp_id: str
    ts_sec: int
    ts_usec: int


def parse_common_header(data: bytes) -> CommonHeader:
    if len(data) < 6:
        raise ValueError("BMP common header needs 6 bytes")
    version, length, mtype = struct.unpack("!BIB", data[:6])
    if version != 3:
        raise ValueError(f"unsupported BMP version {version}")
    if mtype not in MSG_TYPES:
        raise ValueError(f"unknown BMP message type {mtype}")
    return CommonHeader(version, length, MSG_TYPES[mtype])


def parse_per_peer_header(data: bytes) -> PerPeerHeader:
    if len(data) < 42:
        raise ValueError("BMP per-peer header needs 42 bytes")
    ptype, flags = struct.unpack("!BB", data[:2])
    addr_raw = data[10:26]
    if flags & 0x80:  # V flag: IPv6
        addr = str(ipaddress.IPv6Address(addr_raw))
    else:
        addr = str(ipaddress.IPv4Address(addr_raw[12:]))
    peer_as, = struct.unpack("!I", data[26:30])
    bgp_id = str(ipaddress.IPv4Address(data[30:34]))
    ts_sec, ts_usec = struct.unpack("!II", data[34:42])
    return PerPeerHeader(ptype, flags, addr, peer_as, bgp_id, ts_sec, ts_usec)
