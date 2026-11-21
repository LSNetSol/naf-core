import os, struct, sys, unittest, ipaddress
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from naf.collect.bmp import parse_common_header, parse_per_peer_header
from naf.collect.rtr import parse_ipv4_prefix_pdu
from naf.collect.syslog_ipfix import parse_syslog
from naf.collect.gnmi import parse_notification
from naf.normalize import bgp_update_event, validate_event


class TestBmp(unittest.TestCase):
    def test_common_header(self):
        h = parse_common_header(struct.pack("!BIB", 3, 100, 0))
        self.assertEqual((h.version, h.length, h.msg_type), (3, 100, "route_monitoring"))

    def test_bad_version(self):
        with self.assertRaises(ValueError):
            parse_common_header(struct.pack("!BIB", 2, 100, 0))

    def test_per_peer_header_ipv4(self):
        addr = b"\x00" * 12 + ipaddress.IPv4Address("192.0.2.1").packed
        data = struct.pack("!BB8s16sI4sII", 0, 0, b"\x00" * 8, addr, 64496,
                           ipaddress.IPv4Address("198.51.100.1").packed, 1700000000, 5)
        p = parse_per_peer_header(data)
        self.assertEqual((p.peer_address, p.peer_as, p.bgp_id, p.ts_sec), ("192.0.2.1", 64496, "198.51.100.1", 1700000000))


class TestRtr(unittest.TestCase):
    def test_ipv4_pdu(self):
        pdu = struct.pack("!BBHIBBBB4sI", 1, 4, 0, 20, 1, 24, 24, 0, ipaddress.IPv4Address("192.0.2.0").packed, 64496)
        announce, vrp = parse_ipv4_prefix_pdu(pdu)
        self.assertTrue(announce)
        self.assertEqual((vrp.prefix, vrp.max_length, vrp.asn), ("192.0.2.0/24", 24, 64496))

    def test_wrong_length(self):
        with self.assertRaises(ValueError):
            parse_ipv4_prefix_pdu(b"\x00" * 10)


class TestSyslogGnmi(unittest.TestCase):
    def test_syslog(self):
        line = "<34>1 2026-11-10T22:14:15.003Z edge-a bgpd 123 ID47 - Neighbor 192.0.2.1 Down"
        r = parse_syslog(line)
        self.assertEqual((r["facility"], r["severity"], r["host"]), (4, 2, "edge-a"))
        self.assertIn("Down", r["message"])

    def test_gnmi_notification(self):
        n = {"timestamp": 1700000000000000000, "prefix": "interfaces/interface[name=eth1]",
             "update": [{"path": "state/oper-status", "val": "DOWN"}]}
        ev = parse_notification(n)
        self.assertEqual(ev[0]["path"], "interfaces/interface[name=eth1]/state/oper-status")
        self.assertEqual(ev[0]["value"], "DOWN")

    def test_normalize(self):
        ev = bgp_update_event(1, 64502, "192.0.2.0/24", [64502, 64496])
        self.assertEqual(validate_event(ev)["kind"], "bgp_update")
        with self.assertRaises(ValueError):
            validate_event({"ts": 1})


if __name__ == "__main__":
    unittest.main()
