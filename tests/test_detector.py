"""Unit tests for the RelayGuard detector. Run: python3 -m unittest -v tests.test_detector"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from relayguard.detector import RelayDetector, FLAG_THRESHOLD  # noqa: E402
from relayguard.simulator import generate  # noqa: E402
from relayguard.evaluate import evaluate  # noqa: E402

LONDON = (51.5074, -0.1278)


def _tx(**kw):
    base = {
        "id": "t", "token": "DPAN-0001", "amount": 10.0,
        "terminal_id": "T-LON-10", "city": "London",
        "lat": LONDON[0], "lon": LONDON[1], "timestamp": 1_762_900_000,
        "apdu_latency_ms": 45, "cdcvm_claimed": False,
        "enroll_lat": LONDON[0], "enroll_lon": LONDON[1],
    }
    base.update(kw)
    return base


class TestSignals(unittest.TestCase):
    def test_clean_local_tap_is_legit(self):
        det = RelayDetector()
        res = det.score(_tx())
        self.assertEqual(res.verdict, "LEGIT")
        self.assertEqual(res.score, 0)

    def test_slow_terminal_alone_not_flagged(self):
        # Elevated latency on its own must not trip a flag (precision guard).
        det = RelayDetector()
        res = det.score(_tx(apdu_latency_ms=170))
        self.assertLess(res.score, FLAG_THRESHOLD)
        self.assertEqual(res.verdict, "LEGIT")

    def test_ghost_tap_is_flagged(self):
        det = RelayDetector()
        det.score(_tx(timestamp=1_762_900_000))  # home tap
        res = det.score(_tx(
            terminal_id="T-BUC-55", city="Bucharest",
            lat=44.4268, lon=26.1025, timestamp=1_762_900_200,
            amount=240.0, apdu_latency_ms=460, cdcvm_claimed=True,
        ))
        self.assertEqual(res.verdict, "RELAY")
        names = {s.name for s in res.signals}
        self.assertIn("extreme_latency", names)
        self.assertIn("impossible_travel", names)

    def test_impossible_travel_detected(self):
        det = RelayDetector()
        det.score(_tx(timestamp=1_762_900_000))
        res = det.score(_tx(lat=44.4268, lon=26.1025, city="Bucharest",
                            timestamp=1_762_900_120, apdu_latency_ms=50))
        names = {s.name for s in res.signals}
        self.assertIn("impossible_travel", names)

    def test_score_capped_at_100(self):
        det = RelayDetector()
        det.score(_tx())
        res = det.score(_tx(
            terminal_id="T-HK-9", lat=22.3193, lon=114.1694, city="Hong Kong",
            timestamp=1_762_900_100, amount=900.0, apdu_latency_ms=800,
            cdcvm_claimed=True))
        self.assertLessEqual(res.score, 100)
        self.assertEqual(res.verdict, "RELAY")


class TestEndToEnd(unittest.TestCase):
    def test_eval_metrics_are_strong(self):
        rows = generate(num_tokens=14, seed=7)
        m = evaluate(rows)
        # The detector should catch the clear cases and keep false positives low.
        self.assertGreaterEqual(m["recall"], 0.75)
        self.assertGreaterEqual(m["precision"], 0.90)
        self.assertLessEqual(m["fpr"], 0.05)
        # Ghost-tap (the loud case) should be caught essentially every time.
        caught = m["caught_by_style"]["ghost_tap"]
        missed = m["missed_by_style"]["ghost_tap"]
        self.assertEqual(missed, 0, f"missed {missed} ghost_tap events")
        self.assertGreater(caught, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
