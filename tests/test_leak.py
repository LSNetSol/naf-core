import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from naf.leak import check_as_path

# 1 and 2 are tier-1 peers; 10 is a customer of 1; 20 a customer of 2; 11 a customer of 10;
# 30 is a customer of both 10 and 20 (a multihomed customer that could leak).
REL = {
    (1, 2): "p2p", (1, 10): "p2c", (2, 20): "p2c", (10, 11): "p2c",
    (10, 30): "p2c", (20, 30): "p2c",
}


class TestLeak(unittest.TestCase):
    def test_valley_free_up_then_down(self):
        # observer 20 receives from 2, which learned from peer 1, which learned from customer 10, origin 11
        self.assertEqual(check_as_path([2, 1, 10, 11], REL)["verdict"], "ok")

    def test_customer_leaks_provider_route_to_other_provider(self):
        # origin 11 -> 10 -> 30 (customer of 10) -> 20 (30 re-exports a provider route to provider 20)
        r = check_as_path([20, 30, 10, 11], REL)
        self.assertEqual(r["verdict"], "leak")

    def test_prepending_is_collapsed(self):
        self.assertEqual(check_as_path([2, 1, 1, 1, 10, 11], REL)["verdict"], "ok")

    def test_missing_relationship_is_unverifiable_not_leak(self):
        self.assertEqual(check_as_path([99, 10, 11], REL)["verdict"], "unverifiable")


if __name__ == "__main__":
    unittest.main()
