"""Tests for the layered detector, the synthetic world and the co-evolution loop.

These run a small version of the arena, so they are a few seconds, not minutes.
Run: python3 -m unittest -v tests.test_adversarial
"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from relayguard import arena, coevolve, redteam                      # noqa: E402
from relayguard.adversary import FAMILY_ORDER, assumed_relay_floor   # noqa: E402
from relayguard.layered import (ALL_LAYERS, BASELINE_LAYERS, LAYERS,  # noqa: E402
                                LayeredDetector)
from relayguard.providers import PROVIDERS                           # noqa: E402

LONDON = (51.5074, -0.1278)


def _tx(**kw):
    base = {
        "token": "TK-1", "provider": "visa", "amount": 10.0, "terminal_id": "T-LON-01",
        "city": "London", "country": "GB", "home_country": "GB", "lat": LONDON[0],
        "lon": LONDON[1], "timestamp": 1_794_000_000, "apdu_latency_ms": 44,
        "cdcvm_claimed": False, "enroll_lat": LONDON[0], "enroll_lon": LONDON[1],
        "token_age_s": 400 * 86400, "expiry_ym": 202809, "aid": PROVIDERS["visa"].aid_prefix,
        "pan_brand": "VISA", "atc": 10, "mcc": "retail", "transit_entitlement": False,
    }
    if "cdcvm" in kw:
        kw["cdcvm_claimed"] = kw.pop("cdcvm")
    base.update(kw)
    return base


class TestLayers(unittest.TestCase):
    def test_clean_tap_is_legit(self):
        d = LayeredDetector.full()
        self.assertEqual(d.score(_tx()).verdict, "LEGIT")

    def test_registry_consistent(self):
        self.assertTrue(set(BASELINE_LAYERS).issubset(ALL_LAYERS))
        self.assertEqual(len(ALL_LAYERS), len(set(ALL_LAYERS)))
        self.assertGreaterEqual(len(ALL_LAYERS), 20)

    def test_expired_card_fires(self):
        d = LayeredDetector.full()
        r = d.score(_tx(expiry_ym=202501, amount=60))
        self.assertEqual(r.verdict, "RELAY")
        self.assertIn("expired_card", {s.name for s in r.signals})

    def test_brand_mixup_fires(self):
        d = LayeredDetector.full()
        r = d.score(_tx(provider="mastercard", pan_brand="MASTERCARD",
                        aid=PROVIDERS["visa"].aid_prefix, amount=300, cdcvm=True))
        self.assertIn("aid_brand_mismatch", {s.name for s in r.signals})
        self.assertEqual(r.verdict, "RELAY")

    def test_cryptogram_replay_fires(self):
        d = LayeredDetector.full()
        d.score(_tx(atc=20, timestamp=1_794_000_000))
        r = d.score(_tx(atc=20, timestamp=1_794_000_600, terminal_id="T-LON-02"))
        self.assertIn("atc_regression", {s.name for s in r.signals})

    def test_transit_misuse_fires(self):
        d = LayeredDetector.full()
        r = d.score(_tx(provider="applepay", pan_brand="MASTERCARD",
                        aid=PROVIDERS["applepay"].aid_prefix, amount=500,
                        transit_entitlement=True, mcc="retail"))
        self.assertIn("transit_misuse", {s.name for s in r.signals})

    def test_plastic_cannot_claim_cdcvm(self):
        d = LayeredDetector.full()
        r = d.score(_tx(provider="visa", amount=300, cdcvm=True))
        self.assertIn("cvm_integrity", {s.name for s in r.signals})

    def test_blocked_tap_does_not_poison_history(self):
        # A flagged tap in a far city must not make the genuine next tap look like impossible travel.
        d = LayeredDetector.full()
        d.score(_tx(timestamp=1_794_000_000, atc=10))
        far = d.score(_tx(lat=22.3, lon=114.1, country="HK", timestamp=1_794_000_200,
                          amount=300, apdu_latency_ms=460, cdcvm=True, terminal_id="MULE-1", atc=11))
        self.assertEqual(far.verdict, "RELAY")
        back = d.score(_tx(timestamp=1_794_000_900, terminal_id="T-LON-01", atc=12))
        self.assertEqual(back.verdict, "LEGIT")

    def test_learn_mode_does_not_block(self):
        d = LayeredDetector.full()
        r = d.score(_tx(expiry_ym=202501, amount=60), learn=True)
        self.assertEqual(r.verdict, "RELAY")          # verdict still computed
        # but nothing was blocked / the tap was absorbed as history (smoke: no exception)


class TestArena(unittest.TestCase):
    N = 8

    @classmethod
    def setUpClass(cls):
        plan = arena.default_plan(cls.N)
        cls.base = arena.run(BASELINE_LAYERS, None, seed=5, plan=plan)
        full = LayeredDetector.full()
        cls.full = arena.run(full.enabled, full.params, seed=5, plan=plan)

    def test_baseline_is_weak(self):
        self.assertLessEqual(len(self.base["robust"]), 4)
        self.assertLess(self.base["prevented"], 0.25)

    def test_full_covers_everything(self):
        self.assertGreaterEqual(len(self.full["robust"]), len(FAMILY_ORDER) - 1)
        self.assertGreaterEqual(self.full["prevented"], 0.95)

    def test_five_fold_improvement(self):
        # the headline claim: the evolved detector covers >=5x the families of the first release
        self.assertGreaterEqual(len(self.full["robust"]), 5 * max(1, len(self.base["robust"])))

    def test_false_positive_budget(self):
        self.assertLessEqual(self.full["fpr"], 0.01)
        self.assertGreaterEqual(self.full["precision"], 0.90)

    def test_every_provider_covered(self):
        for key in PROVIDERS:
            self.assertIn(key, self.full["providers"])
            self.assertGreaterEqual(self.full["providers"][key]["prevented"], 0.80,
                                    f"{key} not robustly covered")


class TestRedTeamAndLoop(unittest.TestCase):
    def test_fuzzer_beats_baseline_but_not_full(self):
        base = redteam.fuzz(BASELINE_LAYERS, None, seed=99, per_family=6, generations=1)
        self.assertGreater(base["leak"], 0.30)         # the five-layer detector leaks badly
        full = LayeredDetector.full()
        hard = redteam.fuzz(full.enabled, full.params, seed=99, per_family=6, generations=1)
        self.assertLess(hard["leak"], 0.05)            # the evolved detector barely leaks

    def test_quick_loop_runs_and_improves(self):
        o = coevolve.run(quick=True, log=lambda *a: None)
        h = o["headline"]
        self.assertGreaterEqual(h["families_covered"][1], 5 * max(1, h["families_covered"][0]))
        self.assertLessEqual(h["fpr"][1], 0.01)
        self.assertGreater(h["value_blocked"][1], 5 * h["value_blocked"][0])
        # the report renders without error
        self.assertIn("Adversarial co-evolution report", coevolve.render_report(o))


if __name__ == "__main__":
    t = time.time()
    unittest.main(exit=False, verbosity=2)
    print(f"\n(total {time.time() - t:.1f}s)")


class TestLockedGaps(unittest.TestCase):
    """The accumulating regression lock: every gap the red team ever found stays closed."""

    def test_fixture_exists_and_is_populated(self):
        from relayguard import gaps
        data = gaps._load()
        self.assertGreaterEqual(len(data.get("gaps", [])), len(FAMILY_ORDER),
                                "locked-gap fixture missing or too small — run gaps --freeze")

    def test_no_locked_gap_has_regressed(self):
        from relayguard import gaps
        fails = gaps.check()
        msg = "; ".join(f"{f['floor_ms']}ms/{f['family']}: £{f['replayed_payoff']:.0f}"
                        f">£{f['locked_max_payoff']:.0f}" for f in fails)
        self.assertEqual(fails, [], f"locked gaps reopened: {msg}")
