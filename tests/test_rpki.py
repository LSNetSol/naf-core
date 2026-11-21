import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from naf.rpki import VRP, validate, VALID, INVALID, NOT_FOUND

VRPS = [VRP("192.0.2.0/24", 24, 64496), VRP("198.51.100.0/24", 25, 64497)]


class TestRov(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(validate("192.0.2.0/24", 64496, VRPS), VALID)

    def test_wrong_origin_is_invalid(self):
        self.assertEqual(validate("192.0.2.0/24", 64511, VRPS), INVALID)

    def test_too_specific_is_invalid(self):
        self.assertEqual(validate("192.0.2.0/25", 64496, VRPS), INVALID)

    def test_within_max_length_is_valid(self):
        self.assertEqual(validate("198.51.100.0/25", 64497, VRPS), VALID)

    def test_not_covered_is_not_found(self):
        self.assertEqual(validate("203.0.113.0/24", 64498, VRPS), NOT_FOUND)

    def test_ipv6_does_not_match_ipv4_vrp(self):
        self.assertEqual(validate("2001:db8::/32", 64496, VRPS), NOT_FOUND)


if __name__ == "__main__":
    unittest.main()
