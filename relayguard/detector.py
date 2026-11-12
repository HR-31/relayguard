"""RelayGuard detector — streaming, issuer-side relay-fraud scoring.

The detector consumes authorization-stream transactions one at a time (in timestamp
order) and maintains per-token state so it can reason about travel speed, terminal
familiarity and velocity across a cardholder's history — exactly the data an issuer
already holds. No hardware changes, no terminal cooperation required.

Each signal maps to a documented relay indicator:
  - apdu latency        -> relay over a network adds measurable round-trip delay
                           (the exact signal NFCGate itself timestamps but never checks)
  - impossible travel   -> one token used in two places too far apart, too fast
  - no-PIN new terminal -> CDCVM claimed + high value + a terminal never seen for this token
  - velocity burst      -> one token sprayed across many terminals in minutes
  - far from home        -> token used far from its enrolled device region
"""
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any

from .geo import haversine_km, implied_speed_kmh

# A transaction scoring >= this is flagged as a probable relay.
FLAG_THRESHOLD = 50

# Rough upper bound on honest contactless round-trip. EMV targets ~300-500ms end to
# end; a local tap's card<->terminal exchange is far quicker. Sustained >150ms at the
# terminal is suspicious, >200ms strongly so.
LATENCY_ELEVATED_MS = 150
LATENCY_HIGH_MS = 200
LATENCY_EXTREME_MS = 400

# Travel speeds that no cardholder achieves between two physical taps.
SPEED_IMPLAUSIBLE_KMH = 400    # faster than driving
SPEED_IMPOSSIBLE_KMH = 900     # faster than a commercial flight
MIN_MOVE_KM = 50               # ignore intra-city GPS jitter

HOME_RADIUS_KM = 500           # beyond this, token is "away from enrolled region"
HIGH_VALUE = 100.0             # above the typical no-PIN contactless ceiling
BURST_WINDOW_S = 300
BURST_COUNT = 3


@dataclass
class Signal:
    name: str
    weight: int
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScoreResult:
    score: int
    verdict: str            # "RELAY" or "LEGIT"
    signals: List[Signal] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "verdict": self.verdict,
            "signals": [s.to_dict() for s in self.signals],
        }


class RelayDetector:
    """Stateful streaming detector. Feed transactions in timestamp order."""

    def __init__(self, threshold: int = FLAG_THRESHOLD):
        self.threshold = threshold
        self._state: Dict[str, Dict[str, Any]] = {}

    def reset(self) -> None:
        self._state.clear()

    def score(self, tx: Dict[str, Any]) -> ScoreResult:
        signals: List[Signal] = []
        token = tx["token"]
        st = self._state.get(token)
        lat, lon, ts = tx["lat"], tx["lon"], tx["timestamp"]

        # 1 - APDU round-trip latency at the terminal.
        lat_ms = tx.get("apdu_latency_ms", 0)
        if lat_ms > LATENCY_EXTREME_MS:
            signals.append(Signal("extreme_latency", 45,
                                  f"{lat_ms} ms round-trip — consistent with a network relay"))
        elif lat_ms > LATENCY_HIGH_MS:
            signals.append(Signal("high_latency", 30,
                                  f"{lat_ms} ms round-trip exceeds the proximity budget"))
        elif lat_ms > LATENCY_ELEVATED_MS:
            signals.append(Signal("elevated_latency", 15,
                                  f"{lat_ms} ms round-trip is elevated"))

        # 2 - Impossible travel vs this token's previous tap.
        #     Skip if the previous tap was itself flagged as relay: its location is
        #     untrustworthy, so punishing the cardholder's genuine next tap for
        #     "travelling back" would just cascade one relay into false positives.
        if st and st["last_ts"] is not None and not st["last_flagged"]:
            dt = ts - st["last_ts"]
            dist = haversine_km(st["last_lat"], st["last_lon"], lat, lon)
            if dist > MIN_MOVE_KM and dt >= 0:
                speed = implied_speed_kmh(dist, dt)
                if speed > SPEED_IMPOSSIBLE_KMH:
                    signals.append(Signal("impossible_travel", 35,
                                          f"{dist:.0f} km in {dt}s ⇒ {speed:.0f} km/h"))
                elif speed > SPEED_IMPLAUSIBLE_KMH:
                    signals.append(Signal("implausible_travel", 20,
                                          f"{dist:.0f} km in {dt}s ⇒ {speed:.0f} km/h"))

        # 3 - CDCVM (no-PIN) claimed + high value + a terminal never seen for this token.
        #     Only once the token has history: a token's first-ever terminal is not
        #     suspicious (everything is new), which would otherwise cost precision.
        seen_terminal = bool(st and tx["terminal_id"] in st["terminals"])
        if st and tx.get("cdcvm_claimed") and tx["amount"] > HIGH_VALUE and not seen_terminal:
            signals.append(Signal("highvalue_nopin_newterminal", 18,
                                  f"£{tx['amount']:.0f} no-PIN at unseen terminal "
                                  f"{tx['terminal_id']}"))

        # 4 - Velocity burst: many taps in a short window.
        if st:
            recent = [t for t in st["recent_ts"] if 0 <= ts - t <= BURST_WINDOW_S]
            if len(recent) >= BURST_COUNT:
                signals.append(Signal("velocity_burst", 15,
                                      f"{len(recent) + 1} taps within "
                                      f"{BURST_WINDOW_S // 60} min"))

        # 5 - Far from the device's enrolled region.
        if "enroll_lat" in tx and "enroll_lon" in tx:
            hd = haversine_km(tx["enroll_lat"], tx["enroll_lon"], lat, lon)
            if hd > HOME_RADIUS_KM:
                signals.append(Signal("far_from_home", 10,
                                      f"{hd:.0f} km from enrolled device region"))

        score = min(100, sum(s.weight for s in signals))
        verdict = "RELAY" if score >= self.threshold else "LEGIT"
        self._update(tx, flagged=(verdict == "RELAY"))
        return ScoreResult(score=score, verdict=verdict, signals=signals)

    def _update(self, tx: Dict[str, Any], flagged: bool) -> None:
        st = self._state.setdefault(tx["token"], {
            "last_lat": None, "last_lon": None, "last_ts": None,
            "terminals": set(), "recent_ts": [], "last_flagged": False,
        })
        st["last_lat"], st["last_lon"], st["last_ts"] = tx["lat"], tx["lon"], tx["timestamp"]
        st["last_flagged"] = flagged
        st["terminals"].add(tx["terminal_id"])
        st["recent_ts"].append(tx["timestamp"])
        st["recent_ts"] = st["recent_ts"][-25:]
