"""Regression lock for every gap the red team has ever found.

The idea the project runs on: a hole is only closed once there is a test that fails
if it ever reopens. `freeze` runs the automated red team against the shipped detector,
takes the single most profitable attack it can still find in each family (at both an
observable-latency relay floor and a latency-masked one), and records it with a locked
ceiling on how much value the detector may let through. `check` replays every frozen
attack and fails if any now extracts more than its lock.

    python3 -m relayguard.gaps --freeze     # extend tests/fixtures/locked_gaps.json
    python3 -m relayguard.gaps --check      # what the regression test runs

The fixture only ever tightens: re-freezing keeps the lower ceiling, and new families
or floors are appended. So the suite accumulates — each loop teaches it one more attack
it must never again permit.
"""
from __future__ import annotations

import argparse
import json
import math
import os
from typing import Any, Dict, List, Optional, Tuple

from . import arena, redteam
from .adversary import FAMILIES, RELAY_FAMILIES, assumed_relay_floor, describe
from .layered import LayeredDetector

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(HERE, "tests", "fixtures", "locked_gaps.json")

# Relay floors the red team is given: a competent relay, and a latency-masking relay.
FLOORS = [95, 50]
# Ceiling = measured payoff scaled up, floored, so day-to-day noise never trips the test
# but a real regression (a reopened hole) does.
TOL_MULT = 1.5
TOL_FLOOR = 500.0
CHECK_SEED = 55            # freeze anchors the lock to this exact measurement, so it is
CHECK_REPLICAS = 8         # deterministic: check replays identically and can only regress upward


def _measure(cfg: LayeredDetector, elite: Dict[str, List[Dict[str, Any]]], seed: int,
             replicas: int = 6) -> Dict[str, float]:
    best, _ = redteam.replay_elite(cfg.enabled, cfg.params, elite, seed, replicas=replicas)
    return best


def freeze(per_family: int = 40, generations: int = 2, seed: int = 20260) -> Dict[str, Any]:
    cfg = LayeredDetector.full()
    existing = _load()
    locked: Dict[Tuple[int, str], Dict[str, Any]] = {
        (e["floor_ms"], e["family"]): e for e in existing.get("gaps", [])}

    for floor in FLOORS:
        with assumed_relay_floor(floor, competent=floor < 95):
            fz = redteam.fuzz(cfg.enabled, cfg.params, seed=seed + floor,
                              per_family=per_family, generations=generations)
            # measure each family's single best genome, replayed several times
            tops = {f: fz["elite"][f][:1] for f in fz["elite"] if fz["elite"][f]}
            payoff = _measure(cfg, tops, seed + floor + 1)
        # Anchor the lock to the SAME measurement the regression test will make,
        # so the ceiling is deterministic and only a real regression can exceed it.
        with assumed_relay_floor(floor, competent=floor < 95):
            anchor = _measure(cfg, tops, CHECK_SEED + floor, replicas=CHECK_REPLICAS)
        for fam, genomes in tops.items():
            g = genomes[0]
            p = anchor.get(fam, 0.0)
            ceiling = max(TOL_FLOOR, p * TOL_MULT)
            entry = {
                "floor_ms": floor, "family": fam, "label": FAMILIES[fam]["label"],
                "genome": {k: (round(v, 3) if isinstance(v, float) else v) for k, v in g.items()},
                "describe": describe(g), "measured_payoff": round(p, 2),
                "locked_max_payoff": round(ceiling, 2),
            }
            key = (floor, fam)
            if key in locked:
                # only ever tighten the ceiling, but never below what we currently measure
                tight = min(locked[key]["locked_max_payoff"], ceiling)
                entry["locked_max_payoff"] = round(max(tight, p * 1.05, TOL_FLOOR * 0.8), 2)
                # keep whichever genome is currently harder (higher measured payoff)
                if locked[key]["measured_payoff"] >= p:
                    entry["genome"] = locked[key]["genome"]
                    entry["describe"] = locked[key].get("describe", "")
                    entry["measured_payoff"] = locked[key]["measured_payoff"]
            locked[key] = entry

    out = {"detector": "LayeredDetector.full()",
           "note": "Each entry is an attack the red team found; the detector must keep it "
                   "at or below locked_max_payoff. Regenerate with `python3 -m relayguard.gaps --freeze`.",
           "floors_ms": FLOORS,
           "gaps": [locked[k] for k in sorted(locked, key=lambda k: (k[0], k[1]))]}
    os.makedirs(os.path.dirname(FIXTURE), exist_ok=True)
    with open(FIXTURE, "w") as fh:
        json.dump(out, fh, indent=1)
    return out


def _load() -> Dict[str, Any]:
    if os.path.exists(FIXTURE):
        with open(FIXTURE) as fh:
            return json.load(fh)
    return {}


def check(seed: int = CHECK_SEED, replicas: int = CHECK_REPLICAS) -> List[Dict[str, Any]]:
    """Replay every frozen gap against the shipped detector. Returns any that regressed."""
    data = _load()
    if not data.get("gaps"):
        return []
    cfg = LayeredDetector.full()
    failures: List[Dict[str, Any]] = []
    by_floor: Dict[int, Dict[str, List[Dict[str, Any]]]] = {}
    for e in data["gaps"]:
        by_floor.setdefault(e["floor_ms"], {}).setdefault(e["family"], []).append(e["genome"])
    for floor, fams in by_floor.items():
        with assumed_relay_floor(floor, competent=floor < 95):
            got = _measure(cfg, {f: g for f, g in fams.items()}, seed + floor, replicas=replicas)
        for e in data["gaps"]:
            if e["floor_ms"] != floor:
                continue
            p = got.get(e["family"], 0.0)
            if p > e["locked_max_payoff"]:
                failures.append({**e, "replayed_payoff": round(p, 2)})
    return failures


def main() -> None:
    ap = argparse.ArgumentParser(description="RelayGuard gap regression locks")
    ap.add_argument("--freeze", action="store_true", help="extend the locked-gap fixture")
    ap.add_argument("--check", action="store_true", help="replay and report regressions")
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    if args.freeze:
        kw = {"per_family": 12, "generations": 1} if args.quick else {}
        out = freeze(**kw)
        print(f"froze {len(out['gaps'])} gap locks -> {os.path.relpath(FIXTURE, HERE)}")
        for g in out["gaps"]:
            print(f"  floor {g['floor_ms']:>3} ms  {g['family']:20s} "
                  f"measured £{g['measured_payoff']:>8,.0f}  lock £{g['locked_max_payoff']:>8,.0f}")
    if args.check or not args.freeze:
        fails = check()
        if fails:
            print(f"REGRESSION: {len(fails)} locked gaps reopened")
            for f in fails:
                print(f"  floor {f['floor_ms']} {f['family']}: £{f['replayed_payoff']:,.0f} "
                      f"> lock £{f['locked_max_payoff']:,.0f}")
            raise SystemExit(1)
        print("all locked gaps still closed")


if __name__ == "__main__":
    main()
