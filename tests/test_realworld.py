"""Tests against the independent Fraud-Detection-Handbook benchmark.

These assert the HONEST properties of running a relay-specialised detector on a generic
card-fraud world: it must not misfire on an unfamiliar legitimate population, and the
simulator must reproduce the Handbook's structure. Recall is deliberately NOT asserted
high — RelayGuard is not a general fraud detector, and scenario 2 (skimmed terminals)
is near-uncatchable without issuer fraud-feedback. That limitation is asserted as a
known fact so the suite documents it rather than hides it.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from relayguard import realworld                                     # noqa: E402
from relayguard.layered import LayeredDetector                       # noqa: E402


class TestSimulator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = realworld.simulate(n_customers=400, n_terminals=1000, nb_days=30, seed=0)

    def test_simulator_produces_labelled_transactions(self):
        self.assertGreater(len(self.raw), 2000)
        scen = {r["TX_FRAUD_SCENARIO"] for r in self.raw}
        self.assertTrue({1, 2, 3}.issubset(scen), "all three fraud scenarios must appear")

    def test_fraud_is_a_plausible_minority(self):
        # The handbook's ~1% is at full scale (5k customers / 10k terminals). The absolute
        # scenario counts (2 terminals, 3 customers per day) don't scale down, so a small
        # sim inflates the rate — assert only that fraud is a present minority.
        frauds = sum(1 for r in self.raw if r["TX_FRAUD"])
        rate = frauds / len(self.raw)
        self.assertTrue(0.003 < rate < 0.20, f"fraud rate {rate:.3f} implausible")

    def test_scenario1_is_over_220(self):
        for r in self.raw:
            if r["TX_FRAUD_SCENARIO"] == 1:
                self.assertGreater(r["TX_AMOUNT"], 220)

    def test_adapter_schema(self):
        rows = realworld.adapt(self.raw[:50])
        need = {"token", "provider", "amount", "terminal_id", "lat", "lon", "timestamp",
                "apdu_latency_ms", "cdcvm_claimed", "atc", "is_fraud", "scenario"}
        self.assertTrue(need.issubset(rows[0]))
        self.assertTrue(all(r2["atc"] > r1["atc"] for r1, r2 in zip(rows, rows[1:])
                            if r1["token"] == r2["token"]))


class TestCrossWorld(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rows = realworld.adapt(realworld.simulate(n_customers=500, n_terminals=1200,
                                                  nb_days=35, seed=0))
        cls.res = realworld.evaluate(rows, LayeredDetector.full())

    def test_low_false_positive_on_independent_world(self):
        # The headline cross-world property: do not misfire on a world never tuned on.
        self.assertLessEqual(self.res["fpr"], 0.005,
                             f"per-tx FPR {self.res['fpr']:.4f} too high on the independent world")

    def test_relay_detector_is_specialised_not_general(self):
        # Honest: recall on generic (non-relay) fraud is low by design.
        self.assertLess(self.res["recall"], 0.30)

    def test_scenario2_is_a_known_gap(self):
        # Skimmed-terminal fraud carries no transaction-level signal: documented limitation.
        self.assertLess(self.res["by_scenario"][2]["recall"], 0.15,
                        "if scenario-2 recall rose, update the docs — the gap narrative changed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
