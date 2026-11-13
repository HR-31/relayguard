"""LayeredDetector — the evolved, defence-in-depth version of RelayGuard.

The original `RelayDetector` (detector.py) has five signals. This module keeps those
as the *baseline layers* and adds the layers that the adversarial co-evolution loop
(coevolve.py) had to deploy each time the red team got through.

Design points
  * Every layer is a small pure function `(tx, ctx, params) -> Signal | None`.
  * Layers belong to an *evidence group*. The score is the sum, over groups, of the
    strongest signal in that group — so two layers looking at the same evidence
    (e.g. absolute and relative latency) never double count.
  * Latency is judged relative to what is normal for the token AND for the terminal
    (a reader that is slow for everyone is not suspicious).
  * A blocked tap never teaches the detector anything: flagged transactions do not
    update a token's trusted history.
  * `enabled` selects which layers run, which is what lets the loop start from the
    baseline and add one counter-measure at a time.

Defensive only: this scores transactions. It contains no attack code.
"""
from __future__ import annotations

import time
from statistics import median, pstdev
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from .detector import ScoreResult, Signal
from .geo import haversine_km, implied_speed_kmh
from .providers import PROVIDERS

FLAG_THRESHOLD = 50
POP_LATENCY_MS = 46.0          # population-typical local tap round-trip
DAY = 86400

DEFAULT_PARAMS: Dict[str, float] = {
    "jump_margin_ms": 55.0,            # relative-latency margin over the expected value
    "churn_window_s": 1800,            # look-back for fresh tokens at one terminal
    "accum_window_s": DAY,             # look-back for latency-anomalous spend
    "accum_threshold": 150.0,
    "fresh_age_s": DAY,                # a token younger than this is "fresh"
    "young_terminal_s": 2 * DAY,
    "term_baseline_min_age_s": 3 * DAY,
    "term_baseline_min_samples": 5,
    "burst_strong_n": 99,              # fresh tokens at one terminal that count as a strong burst
    "burst_counts_unused": 0,          # 1 = never-used tokens count toward a terminal burst too
    "young_spend_threshold": 400.0,
    "atm_daily_limit": 500.0,
    "amount_anomaly_floor": 100.0,
}

_AID_BRAND = {p.aid_prefix: p.brand for p in PROVIDERS.values()}
_DEFAULT_PROVIDER = PROVIDERS["visa"]


class _Tok:
    __slots__ = ("n", "seen", "last_lat", "last_lon", "last_ts", "last_flagged",
                 "terminals", "countries", "recent", "lat_hist", "amt_hist",
                 "last_atc", "atm_terminals", "anom", "areas", "young_spend", "atm_spend")

    def __init__(self) -> None:
        self.n = 0                 # approved taps
        self.seen = 0              # all attempts
        self.last_lat = self.last_lon = self.last_ts = None
        self.last_flagged = False
        self.terminals: set = set()
        self.countries: set = set()
        self.recent: List[Tuple[int, str]] = []
        self.lat_hist: List[Tuple[float, str]] = []   # (raw latency, terminal)
        self.amt_hist: List[float] = []
        self.last_atc: Optional[int] = None
        self.atm_terminals: set = set()
        self.anom: List[Tuple[int, float]] = []
        self.areas: List[Tuple[float, float]] = []    # places this token is known to be used
        self.young_spend: List[Tuple[int, float]] = []   # high-value taps at just-appeared merchants
        self.atm_spend: List[Tuple[int, float]] = []


class _Term:
    __slots__ = ("first_seen", "trusted", "fresh", "excess", "sd", "tokens")

    def __init__(self, ts: int) -> None:
        self.first_seen = ts
        self.trusted: List[float] = []
        self.fresh: List[Tuple[int, str, bool]] = []   # (ts, token, provisioned < 24 h ago)
        self.excess = 0.0          # how much slower than typical this reader is, for everyone
        self.sd = 0.0
        self.tokens: set = set()   # distinct tokens that have ever tapped here


class _Ctx:
    __slots__ = ("tok", "term", "prov", "ts", "limit", "fresh", "adj", "tok_base",
                 "rel_jump", "chronic", "rel_anom", "young_merchant", "area_km")


# --------------------------------------------------------------------------- layers
def latency_tier(tx, c, p):
    ms = tx.get("apdu_latency_ms", 0)
    if ms > 400:
        return Signal("latency_tier", 45, f"{ms} ms round-trip — consistent with a network relay")
    if ms > 200:
        return Signal("latency_tier", 30, f"{ms} ms round-trip exceeds the proximity budget")
    if ms > 150:
        return Signal("latency_tier", 15, f"{ms} ms round-trip is elevated")
    return None


def geo_travel(tx, c, p):
    t = c.tok
    if t.last_ts is None or t.last_flagged:
        return None
    dt = c.ts - t.last_ts
    dist = haversine_km(t.last_lat, t.last_lon, tx["lat"], tx["lon"])
    if dist > 50 and dt >= 0:
        speed = implied_speed_kmh(dist, dt)
        if speed > 900:
            return Signal("geo_travel", 35, f"{dist:.0f} km in {dt}s = {speed:.0f} km/h (impossible)")
        if speed > 400:
            return Signal("geo_travel", 20, f"{dist:.0f} km in {dt}s = {speed:.0f} km/h (implausible)")
    return None


def nopin_new_terminal(tx, c, p):
    t = c.tok
    if (t.seen > 0 and tx.get("cdcvm_claimed") and tx["amount"] > c.limit
            and tx["terminal_id"] not in t.terminals):
        return Signal("nopin_new_terminal", 18,
                      f"£{tx['amount']:.0f} no-PIN at a terminal this token has never used")
    return None


def velocity_burst(tx, c, p):
    recent = [1 for (ts, _) in c.tok.recent if 0 <= c.ts - ts <= 300]
    if len(recent) >= 3:
        return Signal("velocity_burst", 15, f"{len(recent) + 1} taps within 5 min")
    return None


def far_from_home(tx, c, p):
    if "enroll_lat" not in tx:
        return None
    d = haversine_km(tx["enroll_lat"], tx["enroll_lon"], tx["lat"], tx["lon"])
    if d > 500:
        return Signal("far_from_home", 10, f"{d:.0f} km from the cardholder's home region")
    return None


def latency_jump(tx, c, p):
    if c.rel_jump:
        exp = c.tok_base if c.tok_base is not None else POP_LATENCY_MS
        return Signal("latency_jump", 35,
                      f"{tx['apdu_latency_ms']} ms vs ~{exp:.0f} ms expected for this token/terminal")
    return None


def chronic_latency(tx, c, p):
    if c.chronic:
        return Signal("chronic_latency", 35,
                      f"token's typical round-trip is {c.tok_base:.0f} ms — it lives behind a relay")
    return None


def fresh_token_highvalue(tx, c, p):
    if c.fresh and tx.get("cdcvm_claimed") and tx["amount"] > c.limit:
        return Signal("fresh_token_highvalue", 25,
                      f"£{tx['amount']:.0f} no-PIN on a token provisioned "
                      f"{tx['token_age_s'] / 3600:.1f} h ago")
    return None


def fresh_latency_combo(tx, c, p):
    if c.fresh and c.rel_anom:
        return Signal("fresh_latency_combo", 15, "newly provisioned token tapping with relay-like latency")
    return None


def spend_spike(tx, c, p):
    h = c.tok.amt_hist
    if len(h) >= 3 and tx["amount"] > c.limit and tx["amount"] >= 5 * median(h):
        return Signal("spend_spike", 15, f"£{tx['amount']:.0f} is ≥5× this token's typical spend")
    return None


def terminal_fresh_burst(tx, c, p):
    unused_ok = bool(p["burst_counts_unused"])
    if not (c.fresh or (unused_ok and c.tok.seen == 0)):
        return None
    w = p["churn_window_s"]
    others = {tk for (ts, tk, fr) in c.term.fresh
              if 0 <= c.ts - ts <= w and tk != tx["token"] and (fr or unused_ok)}
    if others:
        strong = len(others) >= p["burst_strong_n"]
        return Signal("terminal_fresh_burst", 40 if strong else 25,
                      f"{len(others) + 1} new or never-used tokens at this terminal — cash-out pattern")
    return None


def young_terminal(tx, c, p):
    if c.young_merchant and tx["amount"] > c.limit:
        return Signal("young_terminal", 15, "high-value tap at a merchant terminal first seen < 48 h ago")
    return None


def expired_card(tx, c, p):
    exp = tx.get("expiry_ym")
    if exp is None:
        return None
    g = time.gmtime(c.ts)
    now = g.tm_year * 100 + g.tm_mon
    if exp < now:
        return Signal("expired_card", 60, f"credential expired {exp} but transacting in {now}")
    return None


def aid_brand_mismatch(tx, c, p):
    aid, brand = tx.get("aid"), tx.get("pan_brand")
    if aid is None or brand is None:
        return None
    seen = _AID_BRAND.get(aid)
    if seen is not None and seen != brand:
        return Signal("aid_brand_mismatch", 60, f"{brand} credential presented under a {seen} application ID")
    return None


def cvm_integrity(tx, c, p):
    if not tx.get("cdcvm_claimed") or "provider" not in tx:
        return None
    if not c.prov.is_wallet and tx["amount"] > c.limit:
        return Signal("cvm_integrity", 60, "on-device verification claimed by a plastic card (impossible)")
    if c.prov.is_wallet and tx["amount"] > c.prov.cdcvm_ceiling:
        return Signal("cvm_integrity", 30, f"£{tx['amount']:.0f} exceeds the on-device verification ceiling")
    return None


def atc_regression(tx, c, p):
    atc = tx.get("atc")
    if atc is not None and c.tok.last_atc is not None and atc <= c.tok.last_atc:
        return Signal("atc_regression", 60,
                      f"transaction counter {atc} not above last seen {c.tok.last_atc} (replay)")
    return None


def transit_misuse(tx, c, p):
    if not tx.get("transit_entitlement"):
        return None
    if not c.prov.supports_transit:
        return Signal("transit_misuse", 60, "transit entitlement used by a credential that has none")
    if tx.get("mcc") != "transit" or tx["amount"] > c.prov.transit_ceiling:
        return Signal("transit_misuse", 60,
                      f"express-transit (no-auth) entitlement used for £{tx['amount']:.0f} at a "
                      f"{tx.get('mcc', 'non-transit')} merchant")
    return None


def atm_anomaly(tx, c, p):
    if (tx.get("mcc") == "atm" and tx["amount"] >= 150
            and tx["terminal_id"] not in c.tok.atm_terminals):
        return Signal("atm_anomaly", 20, f"£{tx['amount']:.0f} contactless withdrawal at an ATM new to this token")
    return None


def sustained_velocity(tx, c, p):
    recent = [(ts, tid) for (ts, tid) in c.tok.recent if 0 <= c.ts - ts <= 10800]
    terms = {tid for (_, tid) in recent} | {tx["terminal_id"]}
    if len(recent) >= 5 and len(terms) >= 5:
        return Signal("sustained_velocity", 20, f"{len(recent) + 1} taps at {len(terms)} terminals in 3 h")
    return None


def anomalous_spend_accumulation(tx, c, p):
    if not c.rel_anom:
        return None
    w = p["accum_window_s"]
    total = tx["amount"] + sum(a for (ts, a) in c.tok.anom if 0 <= c.ts - ts <= w)
    if total >= p["accum_threshold"]:
        return Signal("anomalous_spend_accumulation", 20,
                      f"£{total:.0f} of relay-like spend on this token inside the look-back window")
    return None


def new_country(tx, c, p):
    cc, home = tx.get("country"), tx.get("home_country")
    if cc is None or home is None:
        return None
    if cc != home and cc not in c.tok.countries:
        return Signal("new_country", 18, f"first tap in {cc} for a {home} cardholder")
    return None


def anomalous_new_terminal(tx, c, p):
    if c.rel_anom and tx["terminal_id"] not in c.tok.terminals:
        return Signal("anomalous_new_terminal", 15, "relay-like latency at a terminal this token has never used")
    return None


def out_of_area(tx, c, p):
    if c.area_km is not None and c.area_km > 80 and tx["terminal_id"] not in c.tok.terminals:
        return Signal("out_of_area", 12, f"{c.area_km:.0f} km from anywhere this token has been used before")
    return None


def displaced_new_token(tx, c, p):
    if not (c.fresh or c.tok.seen == 0) or "enroll_lat" not in tx:
        return None
    d = haversine_km(tx["enroll_lat"], tx["enroll_lon"], tx["lat"], tx["lon"])
    if d > 80:
        return Signal("displaced_new_token", 15,
                      f"new or never-used token first tapped {d:.0f} km from the cardholder's home")
    return None


def dormant_token_first_use(tx, c, p):
    age = tx.get("token_age_s")
    if (c.tok.seen == 0 and age is not None and age >= p["fresh_age_s"]
            and tx.get("cdcvm_claimed") and tx["amount"] > c.limit):
        return Signal("dormant_token_first_use", 20,
                      f"first ever tap of a wallet provisioned {age / DAY:.1f} days ago is a "
                      f"£{tx['amount']:.0f} no-PIN purchase")
    return None


def young_merchant_accumulation(tx, c, p):
    if not c.young_merchant or tx["amount"] <= c.limit or not c.tok.young_spend:
        return None
    total = tx["amount"] + sum(a for (ts, a) in c.tok.young_spend if 0 <= c.ts - ts <= 7 * DAY)
    if total >= p["young_spend_threshold"]:
        return Signal("young_merchant_accumulation", 25,
                      f"£{total:.0f} of high-value spend at just-appeared merchants in a week")
    return None


def stranger_merchant_highvalue(tx, c, p):
    if c.young_merchant and tx["amount"] > c.limit and c.area_km is not None and c.area_km > 80:
        return Signal("stranger_merchant_highvalue", 20,
                      "high-value tap at a just-appeared merchant somewhere this token has never been")
    return None


def amount_anomaly(tx, c, p):
    """A tap far above what this token has ever spent — account-takeover cash-out or a
    relayed high-value purchase. Judged against the token's OWN history, not an absolute
    threshold, so a habitual big spender is not punished."""
    h = c.tok.amt_hist
    if len(h) < 6 or tx["amount"] <= p["amount_anomaly_floor"]:
        return None
    m = median(h)
    sd = pstdev(h) if len(h) > 1 else 0.0
    # Deliberately a weak, contributing signal (never decisive alone): amount with no
    # other evidence is a poor fraud signal — a real customer makes the occasional big
    # purchase. It lifts borderline cases over the line and is harmless on its own.
    if tx["amount"] >= max(10 * m, m + 7 * sd):
        return Signal("amount_anomaly", 22, f"£{tx['amount']:.0f} is ≥10× this token's usual spend")
    if tx["amount"] >= max(5 * m, m + 5 * sd):
        return Signal("amount_anomaly", 12, f"£{tx['amount']:.0f} is well above this token's usual spend")
    return None


def atm_daily_limit(tx, c, p):
    if tx.get("mcc") != "atm":
        return None
    total = tx["amount"] + sum(a for (ts, a) in c.tok.atm_spend if 0 <= c.ts - ts <= DAY)
    if total >= p["atm_daily_limit"]:
        return Signal("atm_daily_limit", 30, f"£{total:.0f} of contactless ATM withdrawals in 24 h")
    return None


def captive_terminal(tx, c, p):
    t = c.tok
    if (t.n >= 3 and tx["amount"] > c.limit and len(t.terminals) == 1
            and tx["terminal_id"] in t.terminals and len(c.term.tokens) <= 2):
        return Signal("captive_terminal", 35,
                      "token and terminal have only ever dealt with each other, then a high-value tap")
    return None


# name -> (function, evidence group). Order here is display order.
LAYERS: Dict[str, Tuple[Callable, str]] = {
    # --- baseline (what the first release shipped) ---
    "latency_tier": (latency_tier, "latency"),
    "geo_travel": (geo_travel, "geo"),
    "nopin_new_terminal": (nopin_new_terminal, "cvm_context"),
    "velocity_burst": (velocity_burst, "velocity"),
    "far_from_home": (far_from_home, "home"),
    # --- deployed by the co-evolution loop ---
    "latency_jump": (latency_jump, "latency"),
    "chronic_latency": (chronic_latency, "latency"),
    "fresh_token_highvalue": (fresh_token_highvalue, "token_age"),
    "fresh_latency_combo": (fresh_latency_combo, "token_age"),
    "spend_spike": (spend_spike, "spend"),
    "terminal_fresh_burst": (terminal_fresh_burst, "terminal_churn"),
    "young_terminal": (young_terminal, "terminal_age"),
    "expired_card": (expired_card, "protocol_expiry"),
    "aid_brand_mismatch": (aid_brand_mismatch, "protocol_brand"),
    "cvm_integrity": (cvm_integrity, "protocol_cvm"),
    "atc_regression": (atc_regression, "protocol_atc"),
    "transit_misuse": (transit_misuse, "protocol_transit"),
    "atm_anomaly": (atm_anomaly, "atm"),
    "sustained_velocity": (sustained_velocity, "velocity"),
    "anomalous_spend_accumulation": (anomalous_spend_accumulation, "accumulation"),
    "new_country": (new_country, "geo_country"),
    "anomalous_new_terminal": (anomalous_new_terminal, "novel_terminal"),
    # --- latency-independent: deployed when the red team was allowed to mask latency ---
    "out_of_area": (out_of_area, "area"),
    "displaced_new_token": (displaced_new_token, "token_geo"),
    "captive_terminal": (captive_terminal, "collusion"),
    "dormant_token_first_use": (dormant_token_first_use, "token_dormancy"),
    "young_merchant_accumulation": (young_merchant_accumulation, "merchant_accumulation"),
    "stranger_merchant_highvalue": (stranger_merchant_highvalue, "stranger_merchant"),
    "atm_daily_limit": (atm_daily_limit, "atm_limit"),
    "amount_anomaly": (amount_anomaly, "spend"),
}

BASELINE_LAYERS: List[str] = ["latency_tier", "geo_travel", "nopin_new_terminal",
                              "velocity_burst", "far_from_home"]
ALL_LAYERS: List[str] = list(LAYERS)

# The hardened parameter set the loop converged on (see ADVERSARIAL_REPORT.md).
# The hardened parameter set the co-evolution loop converged on (see
# ADVERSARIAL_REPORT.md). full() combines it with every layer, so the shipped
# detector is at least as strong as the loop's converged configuration.
HARDENED_PARAMS: Dict[str, float] = dict(
    DEFAULT_PARAMS, jump_margin_ms=40.0, churn_window_s=DAY, accum_window_s=7 * DAY,
    burst_strong_n=2, burst_counts_unused=1)


class LayeredDetector:
    """Stateful streaming detector with selectable layers. Feed taps in time order."""

    def __init__(self, enabled: Optional[Iterable[str]] = None,
                 params: Optional[Dict[str, float]] = None,
                 threshold: int = FLAG_THRESHOLD) -> None:
        names = list(enabled) if enabled is not None else list(ALL_LAYERS)
        unknown = [n for n in names if n not in LAYERS]
        if unknown:
            raise ValueError(f"unknown layers: {unknown}")
        self.enabled = [n for n in ALL_LAYERS if n in set(names)]
        self.params = dict(DEFAULT_PARAMS)
        if params:
            self.params.update(params)
        self.threshold = threshold
        self._tok: Dict[str, _Tok] = {}
        self._term: Dict[str, _Term] = {}

    @classmethod
    def baseline(cls) -> "LayeredDetector":
        """The five layers of the first release."""
        return cls(enabled=BASELINE_LAYERS)

    @classmethod
    def full(cls) -> "LayeredDetector":
        """Every layer, with the hardened parameters — the recommended configuration."""
        return cls(enabled=ALL_LAYERS, params=HARDENED_PARAMS)

    def reset(self) -> None:
        self._tok.clear()
        self._term.clear()

    # ------------------------------------------------------------------ scoring
    def _context(self, tx: Dict[str, Any]) -> _Ctx:
        p = self.params
        c = _Ctx()
        c.ts = tx["timestamp"]
        c.tok = self._tok.get(tx["token"]) or _Tok()
        c.term = self._term.get(tx["terminal_id"]) or _Term(c.ts)
        c.prov = PROVIDERS.get(tx.get("provider", ""), _DEFAULT_PROVIDER)
        c.limit = c.prov.contactless_limit
        age = tx.get("token_age_s")
        c.fresh = age is not None and age < p["fresh_age_s"]
        c.young_merchant = (tx.get("mcc", "retail") == "retail"
                            and (c.ts - c.term.first_seen) < p["young_terminal_s"])
        if c.tok.n >= 3 and c.tok.areas:
            c.area_km = min(haversine_km(a, b, tx["lat"], tx["lon"]) for a, b in c.tok.areas)
        else:
            c.area_km = None

        # Latency relative to what is normal for this terminal and this token.
        # A reader that is slow for everyone is discounted; a token's history is
        # re-normalised against today's terminal baselines, so a cardholder whose
        # local shop has a slow reader does not look "chronically relayed".
        lat = float(tx.get("apdu_latency_ms", 0))
        excess, sd = self._term_baseline(c.term, c.ts)
        margin = max(p["jump_margin_ms"], 2.5 * sd)
        c.adj = lat - excess
        hist = c.tok.lat_hist
        if len(hist) >= 4:
            c.tok_base = median([raw - self._excess_of(tid, c.ts) for raw, tid in hist])
        else:
            c.tok_base = None
        c.chronic = c.tok_base is not None and c.tok_base >= POP_LATENCY_MS + p["jump_margin_ms"]
        # Never expect less than a population-typical tap: a fast history must not
        # make an ordinary tap look like a jump.
        expected = max(c.tok_base or 0.0, POP_LATENCY_MS)
        c.rel_jump = (not c.chronic) and lat > 0 and c.adj >= expected + margin
        c.rel_anom = c.rel_jump or c.chronic
        return c

    def _term_baseline(self, term: _Term, ts: int) -> Tuple[float, float]:
        p = self.params
        if (len(term.trusted) >= p["term_baseline_min_samples"]
                and ts - term.first_seen >= p["term_baseline_min_age_s"]):
            return term.excess, term.sd
        return 0.0, 0.0

    def _excess_of(self, terminal_id: str, ts: int) -> float:
        term = self._term.get(terminal_id)
        return self._term_baseline(term, ts)[0] if term is not None else 0.0

    def score(self, tx: Dict[str, Any], learn: bool = False) -> ScoreResult:
        """Score one tap. With `learn=True` the verdict is still returned but the tap
        is absorbed as trusted history — use it to bootstrap baselines from a period
        of known-clean traffic, exactly as an issuer would from its own history."""
        c = self._context(tx)
        p = self.params
        fired: List[Signal] = []
        best: Dict[str, int] = {}
        for name in self.enabled:
            fn, group = LAYERS[name]
            sig = fn(tx, c, p)
            if sig is not None:
                fired.append(sig)
                if sig.weight > best.get(group, 0):
                    best[group] = sig.weight
        score = min(100, sum(best.values()))
        verdict = "RELAY" if score >= self.threshold else "LEGIT"
        self._update(tx, c, verdict == "RELAY" and not learn, learn)
        return ScoreResult(score=score, verdict=verdict, signals=fired)

    def _update(self, tx: Dict[str, Any], c: _Ctx, flagged: bool, learn: bool = False) -> None:
        t, term = c.tok, c.term
        self._tok[tx["token"]] = t
        self._term[tx["terminal_id"]] = term
        tid = tx["terminal_id"]

        # Attempts are always remembered (velocity, last position, fresh-token bursts).
        t.seen += 1
        t.last_lat, t.last_lon, t.last_ts = tx["lat"], tx["lon"], c.ts
        t.last_flagged = flagged
        t.recent.append((c.ts, tid))
        if len(t.recent) > 40:
            del t.recent[:-40]
        if len(term.tokens) < 64:
            term.tokens.add(tx["token"])
        if c.fresh or t.seen == 1:              # newly provisioned, or this is its first ever tap
            term.fresh.append((c.ts, tx["token"], c.fresh))
            if len(term.fresh) > 60:
                del term.fresh[:-60]
        if flagged:
            return                    # a blocked tap never becomes trusted history

        # Terminal baselines are learned only from approved taps by established,
        # non-anomalous tokens (or from known-clean history), so a mule terminal
        # cannot whitelist itself with its own relayed traffic.
        if learn or (t.n >= 3 and not c.chronic):
            term.trusted.append(float(tx.get("apdu_latency_ms", 0)))
            if len(term.trusted) > 30:
                del term.trusted[:-30]
            term.excess = max(0.0, median(term.trusted) - POP_LATENCY_MS)
            term.sd = pstdev(term.trusted) if len(term.trusted) > 1 else 0.0
        t.n += 1
        t.terminals.add(tid)
        if tx.get("country") is not None:
            t.countries.add(tx["country"])
        t.lat_hist.append((float(tx.get("apdu_latency_ms", 0)), tid))
        if len(t.lat_hist) > 20:
            del t.lat_hist[:-20]
        t.amt_hist.append(tx["amount"])
        if len(t.amt_hist) > 20:
            del t.amt_hist[:-20]
        atc = tx.get("atc")
        if atc is not None and (t.last_atc is None or atc > t.last_atc):
            t.last_atc = atc
        if tx.get("mcc") == "atm":
            t.atm_terminals.add(tid)
            t.atm_spend.append((c.ts, tx["amount"]))
            if len(t.atm_spend) > 20:
                del t.atm_spend[:-20]
        if c.young_merchant and tx["amount"] > c.limit:
            t.young_spend.append((c.ts, tx["amount"]))
            if len(t.young_spend) > 20:
                del t.young_spend[:-20]
        if len(t.areas) < 8 and all(haversine_km(a, b, tx["lat"], tx["lon"]) > 60 for a, b in t.areas):
            t.areas.append((tx["lat"], tx["lon"]))
        if c.rel_anom:
            t.anom.append((c.ts, tx["amount"]))
            if len(t.anom) > 40:
                del t.anom[:-40]
