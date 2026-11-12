"""Synthetic authorization-stream generator for RelayGuard.

Produces a labelled stream mixing honest contactless taps with two relay styles:
  * "ghost_tap"  — the classic cross-border cash-out: far city, big network latency,
                   high value + forged no-PIN, shortly after a genuine home tap.
  * "stealth"    — a domestic relay with only moderate latency and no geo jump; the
                   hard case that keeps recall honest (detector should miss some).

Honest taps occasionally carry elevated latency (a slow terminal) so the detector's
precision is tested too. All rows carry an `is_relay` ground-truth label used ONLY by
the evaluator / dashboard metrics — the detector never reads it.
"""
import random
from typing import List, Dict, Any

HOME_CITIES = [
    ("London", 51.5074, -0.1278), ("Manchester", 53.4808, -2.2426),
    ("Birmingham", 52.4862, -1.8904), ("Leeds", 53.8008, -1.5491),
    ("Glasgow", 55.8642, -4.2518), ("Bristol", 51.4545, -2.5879),
    ("Liverpool", 53.4084, -2.9916), ("Edinburgh", 55.9533, -3.1883),
]
FAR_CITIES = [
    ("Bucharest", 44.4268, 26.1025), ("Warsaw", 52.2297, 21.0122),
    ("Sao Paulo", -23.5558, -46.6396), ("Moscow", 55.7558, 37.6173),
    ("Hong Kong", 22.3193, 114.1694), ("Lagos", 6.5244, 3.3792),
]

T0 = 1_762_900_000  # fixed base epoch for reproducibility


def _jit(v: float, amt: float, rng: random.Random) -> float:
    return v + rng.uniform(-amt, amt)


def generate(num_tokens: int = 14, seed: int = 7) -> List[Dict[str, Any]]:
    rng = random.Random(seed)
    rows: List[Dict[str, Any]] = []
    tid = 0

    for i in range(num_tokens):
        token = f"DPAN-{4000 + i:04d}"
        home_city, hlat, hlon = rng.choice(HOME_CITIES)
        home_terminals = [f"T-{home_city[:3].upper()}-{rng.randint(10, 99)}"
                          for _ in range(rng.randint(2, 4))]
        t = T0 + rng.randint(0, 36_000)

        # 6-12 honest taps spread over time around home.
        legit_rows = []
        for _ in range(rng.randint(6, 12)):
            t += rng.randint(1800, 36_000)  # 0.5-10h apart
            amount = round(rng.choice([
                rng.uniform(2, 25), rng.uniform(5, 40),
                rng.uniform(40, 95), rng.uniform(110, 260),
            ]), 2)
            slow = rng.random() < 0.06  # ~6% slow terminals (precision stressor)
            latency = int(max(8, rng.gauss(165, 35) if slow else rng.gauss(46, 14)))
            row = {
                "id": f"tx{tid:05d}", "token": token,
                "amount": amount,
                "terminal_id": rng.choice(home_terminals),
                "city": home_city,
                "lat": _jit(hlat, 0.04, rng), "lon": _jit(hlon, 0.04, rng),
                "timestamp": t,
                "apdu_latency_ms": latency,
                "cdcvm_claimed": amount > 100 and rng.random() < 0.9,
                "enroll_lat": hlat, "enroll_lon": hlon,
                "attack": "", "is_relay": False,
            }
            tid += 1
            legit_rows.append(row)
        rows.extend(legit_rows)

        # ~55% of tokens get a relay event.
        if rng.random() < 0.55 and legit_rows:
            anchor = rng.choice(legit_rows)
            style = rng.choices(["ghost_tap", "stealth"], weights=[0.65, 0.35])[0]
            if style == "ghost_tap":
                fc, flat, flon = rng.choice(FAR_CITIES)
                row = {
                    "id": f"tx{tid:05d}", "token": token,
                    "amount": round(max(20, rng.gauss(225, 70)), 2),
                    "terminal_id": f"T-{fc[:3].upper()}-{rng.randint(10, 99)}",
                    "city": fc,
                    "lat": _jit(flat, 0.03, rng), "lon": _jit(flon, 0.03, rng),
                    "timestamp": anchor["timestamp"] + rng.randint(90, 420),
                    "apdu_latency_ms": int(max(180, rng.gauss(430, 110))),
                    "cdcvm_claimed": True,  # forged on-device verification
                    "enroll_lat": anchor["enroll_lat"], "enroll_lon": anchor["enroll_lon"],
                    "attack": "ghost_tap", "is_relay": True,
                }
            else:  # stealth domestic relay
                dc, dlat, dlon = rng.choice([c for c in HOME_CITIES
                                             if c[0] != anchor["city"]])
                amt = round(rng.choice([rng.uniform(15, 80), rng.uniform(105, 190)]), 2)
                row = {
                    "id": f"tx{tid:05d}", "token": token,
                    "amount": amt,
                    "terminal_id": f"T-{dc[:3].upper()}-{rng.randint(10, 99)}",
                    "city": dc,
                    "lat": _jit(dlat, 0.03, rng), "lon": _jit(dlon, 0.03, rng),
                    "timestamp": anchor["timestamp"] + rng.randint(120, 500),
                    "apdu_latency_ms": int(max(120, rng.gauss(205, 45))),
                    "cdcvm_claimed": amt > 100,
                    "enroll_lat": anchor["enroll_lat"], "enroll_lon": anchor["enroll_lon"],
                    "attack": "stealth", "is_relay": True,
                }
            tid += 1
            rows.append(row)

    rows.sort(key=lambda r: r["timestamp"])
    return rows


def summary(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    return {
        "total": len(rows),
        "relay": sum(1 for r in rows if r["is_relay"]),
        "legit": sum(1 for r in rows if not r["is_relay"]),
        "ghost_tap": sum(1 for r in rows if r["attack"] == "ghost_tap"),
        "stealth": sum(1 for r in rows if r["attack"] == "stealth"),
    }
