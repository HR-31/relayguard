"""Red team: a synthetic payment world plus the attack families used to stress it.

Everything here produces *synthetic transaction records* — rows of features an issuer
would see in an authorization stream. There is no NFC, card, terminal or network code;
nothing in this module can touch a real payment system. It exists so the detector can
be attacked, measured and hardened in a closed loop (see coevolve.py).

World
    ~480 cardholder tokens across six providers, 20 simulated days (the first 6 are a
    clean learning period), realistic benign
    behaviour: home terminals, a few readers that are slow for everyone, trips abroad,
    shopping sprees, newly provisioned wallets, ATM and transit use.

Attack families
    Each family is a region of "attacker parameter space" (a genome). `typical`
    samples the textbook version of the technique; `space` is the full legal range the
    fuzzer in redteam.py may explore. A relay can never beat physics: its round-trip
    latency has a floor (RELAY_FLOOR_MS).
"""
from __future__ import annotations

import math
import random
from contextlib import contextmanager
from typing import Any, Callable, Dict, Iterator, List, Optional

from .providers import PROVIDERS

T0 = 1_794_000_000          # early November 2026
DAY = 86400
HOUR = 3600
RELAY_FLOOR_MS = 95         # assumed physical floor for a relayed round-trip
_FLOOR = [float(RELAY_FLOOR_MS)]
_LAT_CAP: List[Optional[float]] = [None]   # when set, the fuzzer only tries near-floor latencies


def relay_floor() -> float:
    return _FLOOR[0]


@contextmanager
def assumed_relay_floor(ms: float, competent: bool = False) -> Iterator[None]:
    """Give the red team a different latency floor (e.g. a latency-masking relay).
    Used to test how much protection survives if the core assumption is wrong.
    With `competent=True` the fuzzer only tries latencies within 50 ms of the floor —
    an attacker who can hide latency would not volunteer a slow tap."""
    old, old_cap = _FLOOR[0], _LAT_CAP[0]
    _FLOOR[0] = float(ms)
    _LAT_CAP[0] = float(ms) + 50.0 if competent else None
    try:
        yield
    finally:
        _FLOOR[0], _LAT_CAP[0] = old, old_cap


def _shaped(r: random.Random) -> float:
    """Latency of a relay tuned to sit as close to the floor as it comfortably can."""
    return r.uniform(_FLOOR[0] + 5, _FLOOR[0] + 53)

GB_CITIES = [
    ("London", 51.5074, -0.1278), ("Manchester", 53.4808, -2.2426),
    ("Birmingham", 52.4862, -1.8904), ("Leeds", 53.8008, -1.5491),
    ("Glasgow", 55.8642, -4.2518), ("Bristol", 51.4545, -2.5879),
    ("Liverpool", 53.4084, -2.9916), ("Edinburgh", 55.9533, -3.1883),
]
NEAR_ABROAD = [
    ("Paris", "FR", 48.8566, 2.3522), ("Amsterdam", "NL", 52.3676, 4.9041),
    ("Brussels", "BE", 50.8503, 4.3517), ("Dublin", "IE", 53.3498, -6.2603),
    ("Madrid", "ES", 40.4168, -3.7038), ("Berlin", "DE", 52.5200, 13.4050),
]
NEAR_CODES = ["FR", "NL", "BE", "IE", "ES", "DE"]
FAR_CODES = ["RO", "TR", "BR", "NG", "HK", "AE"]

PROVIDER_MIX = [("visa", 0.20), ("mastercard", 0.20), ("amex", 0.08),
                ("googlepay", 0.20), ("applepay", 0.20), ("eftpos", 0.12)]
WALLETS = ("googlepay", "applepay")
PLASTIC = ("visa", "mastercard", "amex")


def offset(lat: float, lon: float, dist_km: float, bearing_deg: float):
    b = math.radians(bearing_deg)
    dlat = (dist_km * math.cos(b)) / 111.0
    dlon = (dist_km * math.sin(b)) / (111.0 * max(0.2, math.cos(math.radians(lat))))
    return max(-80.0, min(80.0, lat + dlat)), ((lon + dlon + 180.0) % 360.0) - 180.0


# ============================================================================ world
class World:
    def __init__(self, seed: int = 1, n_tokens: int = 520, days: int = 20,
                 warmup_days: int = 6) -> None:
        self.rng = random.Random(seed)
        self.t0 = T0
        self.t_end = T0 + days * DAY
        self.t_eval = T0 + warmup_days * DAY      # metrics only count taps after this
        self._n = 0
        self.tokens: Dict[str, Dict[str, Any]] = {}
        self.benign: Dict[str, List[Dict[str, Any]]] = {}
        self.attack_rows: List[Dict[str, Any]] = []
        self._build_terminals()
        self._build_tokens(n_tokens)
        self._victims = [t for t in self.tokens.values() if t["eligible"]]
        self.rng.shuffle(self._victims)
        self._used: set = set()
        self.mature = [t for t in self.tokens.values() if not t["fresh"]]

    # ------------------------------------------------------------- construction
    def _build_terminals(self) -> None:
        r = self.rng
        self.city: List[Dict[str, Any]] = []
        for name, lat, lon in GB_CITIES:
            code = name[:3].upper()
            retail = [f"T-{code}-{i:02d}" for i in range(40)]
            self.city.append({
                "name": name, "lat": lat, "lon": lon, "code": code, "retail": retail,
                "slow": set(r.sample(retail, 2)),
                "atm": [f"ATM-{code}-{i}" for i in range(4)],
                "transit": [f"TR-{code}-{i}" for i in range(6)],
            })
        self.abroad = [{"name": n, "cc": cc, "lat": la, "lon": lo,
                        "retail": [f"T-{n[:3].upper()}-{i:02d}" for i in range(15)]}
                       for (n, cc, la, lo) in NEAR_ABROAD]

    def _pick_provider(self) -> str:
        x, acc = self.rng.random(), 0.0
        for key, w in PROVIDER_MIX:
            acc += w
            if x <= acc:
                return key
        return PROVIDER_MIX[-1][0]

    def _build_tokens(self, n: int) -> None:
        r = self.rng
        for i in range(n):
            fresh = r.random() < 0.05
            prov = r.choice(WALLETS) if fresh else self._pick_provider()
            ci = r.randrange(len(self.city))
            c = self.city[ci]
            tok = {
                "token": f"TK-{i:05d}", "provider": prov, "ci": ci,
                "home_lat": c["lat"], "home_lon": c["lon"],
                "home_terms": r.sample(c["retail"], 4),
                "atm_user": r.random() < 0.30, "home_atm": r.choice(c["atm"]),
                "fresh": fresh,
                "provision_ts": (T0 + r.uniform(6.5, 17) * DAY) if fresh
                else (T0 - r.uniform(30, 900) * DAY),
                "expiry_ym": r.choice([202703, 202709, 202802, 202808, 202905]),
                "atc0": r.randint(5, 400),
                "trip": (not fresh) and r.random() < 0.08,
                "spree": False, "dtrip": False,
            }
            tok["spree"] = (not fresh) and (not tok["trip"]) and r.random() < 0.05
            tok["dtrip"] = ((not fresh) and not tok["trip"] and not tok["spree"]
                            and r.random() < 0.10)
            self.tokens[tok["token"]] = tok
            rows = self._benign_rows(tok)
            self.benign[tok["token"]] = rows
            tok["eligible"] = (not fresh and not tok["trip"] and not tok["spree"]
                               and not tok["dtrip"] and len(rows) >= 10)

    def row(self, tok: Dict[str, Any], ts: float, amount: float, terminal_id: str,
            lat: float, lon: float, city: str, country: str, latency: float,
            mcc: str = "retail", cdcvm: Optional[bool] = None, transit: bool = False,
            attack: str = "", sid: Optional[int] = None) -> Dict[str, Any]:
        prov = PROVIDERS[tok["provider"]]
        amount = round(max(1.0, amount), 2)
        self._n += 1
        return {
            "id": f"{'a' if attack else 'b'}{self._n:06d}", "token": tok["token"],
            "provider": tok["provider"], "amount": amount, "terminal_id": terminal_id,
            "city": city, "country": country, "lat": lat, "lon": lon,
            "timestamp": int(ts), "apdu_latency_ms": int(round(latency)),
            "cdcvm_claimed": (prov.is_wallet and amount > prov.contactless_limit)
            if cdcvm is None else cdcvm,
            "enroll_lat": tok["home_lat"], "enroll_lon": tok["home_lon"],
            "home_country": "GB", "token_age_s": int(ts - tok["provision_ts"]),
            "expiry_ym": tok["expiry_ym"], "aid": prov.aid_prefix, "pan_brand": prov.brand,
            "atc": 0, "mcc": mcc, "transit_entitlement": transit,
            "attack": attack, "is_relay": bool(attack), "scn": sid,
        }

    def _latency(self, terminal_id: str, slow: set) -> float:
        r = self.rng
        if terminal_id in slow:
            return max(100.0, r.gauss(165, 35))
        return max(12.0, r.gauss(46, 14))

    def _retail_amount(self) -> float:
        r = self.rng
        x = r.random()
        if x < 0.35:
            return r.uniform(2, 15)
        if x < 0.70:
            return r.uniform(10, 45)
        if x < 0.90:
            return r.uniform(40, 98)
        return r.uniform(105, 320)

    def _benign_rows(self, tok: Dict[str, Any]) -> List[Dict[str, Any]]:
        r, c = self.rng, self.city[tok["ci"]]
        prov = PROVIDERS[tok["provider"]]
        start = max(self.t0, tok["provision_ts"] + 600)
        n = r.randint(4, 10) if tok["fresh"] else r.randint(18, 32)
        times = sorted(r.uniform(start, self.t_end) for _ in range(n))
        kept: List[float] = []
        for t in times:
            if not kept or t - kept[-1] >= 1200:
                kept.append(t)

        trip = None
        if tok["trip"]:
            a = self.t0 + r.uniform(8, 15) * DAY
            trip = (a, a + r.uniform(2, 3.5) * DAY, r.choice(self.abroad))
            kept = [t for t in kept if t < trip[0] - 10 * HOUR or t > trip[1] + 10 * HOUR]
        dtrip = None
        if tok["dtrip"]:                            # a few days in another UK city
            a = self.t0 + r.uniform(7, 16) * DAY
            dtrip = (a, a + r.uniform(1, 3) * DAY,
                     r.choice([x for i, x in enumerate(self.city) if i != tok["ci"]]))
            kept = [t for t in kept if t < dtrip[0] - 6 * HOUR or t > dtrip[1] + 6 * HOUR]
        spree = None
        if tok["spree"]:
            s = self.t0 + r.uniform(7, 18) * DAY
            spree = (s, s + 3 * HOUR)
            kept = [t for t in kept if t < spree[0] - HOUR or t > spree[1] + HOUR]

        rows: List[Dict[str, Any]] = []

        def home(t: float, forced_amount: Optional[float] = None) -> None:
            jl, jo = c["lat"] + r.uniform(-.04, .04), c["lon"] + r.uniform(-.04, .04)
            x = r.random()
            if forced_amount is None and x < 0.05:                    # transit gate
                tid = r.choice(c["transit"])
                rows.append(self.row(tok, t, r.uniform(1.5, 8), tid, jl, jo, c["name"], "GB",
                                     max(12.0, r.gauss(46, 14)), mcc="transit",
                                     transit=prov.supports_transit))
                return
            if forced_amount is None and x < 0.08 and tok["atm_user"]:  # cash machine
                tid = tok["home_atm"] if r.random() < 0.9 else r.choice(c["atm"])
                rows.append(self.row(tok, t, r.choice([20, 40, 60, 100, 200, 300]), tid, jl, jo,
                                     c["name"], "GB", max(12.0, r.gauss(46, 14)),
                                     mcc="atm", cdcvm=False))
                return
            y = r.random()
            if y < 0.86:
                tid = r.choice(tok["home_terms"])
            elif y < 0.99:
                tid = r.choice(c["retail"])
            else:
                self._n += 1
                tid = f"T-NEW-{self._n:06d}"                           # a shop that just opened
            amt = forced_amount if forced_amount is not None else self._retail_amount()
            rows.append(self.row(tok, t, amt, tid, jl, jo, c["name"], "GB",
                                 self._latency(tid, c["slow"])))

        for t in kept:
            home(t)
        if tok["fresh"] and r.random() < 0.10:      # new phone, big purchase on day one
            home(start + r.uniform(1800, 20 * HOUR), forced_amount=r.uniform(110, 300))
        if trip:
            a, b, ab = trip
            for _ in range(r.randint(3, 6)):
                t = r.uniform(a, b)
                rows.append(self.row(tok, t, self._retail_amount(), r.choice(ab["retail"]),
                                     ab["lat"] + r.uniform(-.03, .03), ab["lon"] + r.uniform(-.03, .03),
                                     ab["name"], ab["cc"], max(12.0, r.gauss(46, 14))))
        if dtrip:
            a, b, dc = dtrip
            for _ in range(r.randint(2, 5)):
                tid = r.choice(dc["retail"])
                rows.append(self.row(tok, r.uniform(a, b), self._retail_amount(), tid,
                                     dc["lat"] + r.uniform(-.04, .04), dc["lon"] + r.uniform(-.04, .04),
                                     dc["name"], "GB", self._latency(tid, dc["slow"])))
        if spree:
            t = spree[0]
            for tid in r.sample(c["retail"], r.randint(6, 8)):
                rows.append(self.row(tok, t, r.uniform(5, 60), tid,
                                     c["lat"] + r.uniform(-.04, .04), c["lon"] + r.uniform(-.04, .04),
                                     c["name"], "GB", self._latency(tid, c["slow"])))
                t += r.uniform(360, 1500)
        rows.sort(key=lambda x: x["timestamp"])
        return rows

    # --------------------------------------------------------------- red-team API
    def alloc_victim(self, pred: Callable[[Dict[str, Any]], bool]) -> Optional[Dict[str, Any]]:
        for t in self._victims:
            if t["token"] not in self._used and pred(t):
                self._used.add(t["token"])
                return t
        return None

    def pick_anchor(self, tok: Dict[str, Any], need_s: float, rng: random.Random):
        rows = self.benign[tok["token"]]
        cand = [x for i, x in enumerate(rows)
                if i >= 5 and x["timestamp"] >= self.t_eval + HOUR
                and x["timestamp"] + need_s <= self.t_end - HOUR]
        return rng.choice(cand) if cand else None

    def clear_benign(self, tok: Dict[str, Any], t_from: float, t_to: float) -> None:
        """The cardholder is not tapping elsewhere while the attack is in progress."""
        self.benign[tok["token"]] = [x for x in self.benign[tok["token"]]
                                     if not (t_from < x["timestamp"] <= t_to)]

    def attacker_token(self, holder: Dict[str, Any], provision_ts: float,
                       rng: random.Random) -> Dict[str, Any]:
        """A stolen card provisioned into an attacker-held wallet."""
        self._n += 1
        tok = {"token": f"AT-{self._n:06d}", "provider": rng.choice(WALLETS),
               "home_lat": holder["home_lat"], "home_lon": holder["home_lon"],
               "provision_ts": provision_ts, "expiry_ym": holder["expiry_ym"], "atc0": 0}
        self.tokens[tok["token"]] = tok
        return tok

    def finalize(self) -> List[Dict[str, Any]]:
        rows = [x for lst in self.benign.values() for x in lst] + self.attack_rows
        rows.sort(key=lambda x: (x["timestamp"], x["id"]))
        counter: Dict[str, int] = {}
        for x in rows:
            cur = counter.get(x["token"], self.tokens[x["token"]]["atc0"])
            if x.get("_replay"):
                x["atc"] = max(1, cur - self.rng.randint(0, 2))   # a re-used cryptogram
            else:
                cur += 1
                x["atc"] = cur
                counter[x["token"]] = cur
        return rows


# ================================================================= family builders
def _jit(v: float, rng: random.Random, pct: float = 0.05) -> float:
    return v * rng.uniform(1 - pct, 1 + pct)


def _mature_relay(w: World, rng: random.Random, sid: int, g: Dict[str, Any], *, fam: str,
                  where: str, pred: Callable, pin: bool = False, distinct: bool = False,
                  atm: bool = False) -> List[Dict[str, Any]]:
    tok = w.alloc_victim(pred)
    if tok is None:
        return []
    n = int(g.get("n_taps", 1))
    anchor = w.pick_anchor(tok, g["gap_s"] + n * g.get("tap_gap_s", 60) * 1.1 + HOUR, rng)
    if anchor is None:
        return []
    prov = PROVIDERS[tok["provider"]]
    t = anchor["timestamp"] + g["gap_s"]
    if atm:
        c = rng.choice([x for i, x in enumerate(w.city) if i != tok["ci"]])
        lat, lon, city, cc = c["lat"], c["lon"], c["name"], "GB"
        base_tid = rng.choice(c["atm"])
    else:
        bearing = rng.uniform(100, 200) if where == "far" else rng.uniform(0, 360)
        lat, lon = offset(anchor["lat"], anchor["lon"], g["dist_km"], bearing)
        cc = {"domestic": "GB", "near": rng.choice(NEAR_CODES), "far": rng.choice(FAR_CODES)}[where]
        city, base_tid = f"mule-{cc}", f"MULE-{sid}"
    rows = []
    for k in range(n):
        amount = _jit(g["amount"], rng)
        tid = base_tid if (atm or not distinct) else f"{base_tid}-{k}"
        rows.append(w.row(
            tok, t, amount, tid, lat + rng.uniform(-.01, .01), lon + rng.uniform(-.01, .01),
            city, cc, max(_FLOOR[0], g["lat"] + rng.uniform(-4, 4)),
            mcc="atm" if atm else "retail",
            cdcvm=(prov.is_wallet and amount > prov.contactless_limit and not pin),
            attack=fam, sid=sid))
        t += _jit(g.get("tap_gap_s", 60), rng, 0.1)
    w.clear_benign(tok, anchor["timestamp"], rows[-1]["timestamp"] + 1800)
    return rows


def _fresh(w: World, rng: random.Random, sid: int, g: Dict[str, Any], *, fam: str):
    holder = rng.choice(w.mature)
    n_tok, n_taps = int(g.get("n_tokens", 1)), int(g.get("n_taps", 1))
    span = n_tok * n_taps * g["tap_gap_s"] * 1.1 + 2 * HOUR
    if span > w.t_end - w.t_eval - 8 * HOUR:
        return []
    t = rng.uniform(w.t_eval + 6 * HOUR, w.t_end - span)
    abroad = bool(g.get("abroad", 0))
    lat, lon = offset(holder["home_lat"], holder["home_lon"], g["dist_km"], rng.uniform(0, 360))
    cc = rng.choice(NEAR_CODES) if abroad else "GB"
    rows = []
    for _ in range(n_tok):
        atok = w.attacker_token(holder, t - g["age_s"], rng)
        for _ in range(n_taps):
            rows.append(w.row(atok, t, _jit(g["amount"], rng), f"MULE-{sid}", lat, lon,
                              f"mule-{cc}", cc, max(_FLOOR[0], g["lat"] + rng.uniform(-4, 4)),
                              attack=fam, sid=sid))
            t += _jit(g["tap_gap_s"], rng, 0.1)
    return rows


def _seasoned(w: World, rng: random.Random, sid: int, g: Dict[str, Any], *, fam: str):
    holder = rng.choice(w.mature)
    s_n, c_n = int(g["season_taps"]), int(g["n_cash"])
    window = w.t_end - w.t_eval - 4 * HOUR
    season_span = s_n * g["season_gap_s"] * 1.1
    while c_n > 1 and season_span + c_n * g["cash_gap_s"] * 1.1 > window:
        c_n -= 1
    span = season_span + c_n * g["cash_gap_s"] * 1.1
    if span > window:
        return []
    t = rng.uniform(w.t_eval + 2 * HOUR, w.t_end - span - HOUR)
    atok = w.attacker_token(holder, t - HOUR, rng)
    lat, lon = offset(holder["home_lat"], holder["home_lon"], rng.uniform(5, 300), rng.uniform(0, 360))
    rows = []

    def tap(amount: float) -> None:
        rows.append(w.row(atok, t, amount, f"MULE-{sid}", lat, lon, "mule-GB", "GB",
                          max(_FLOOR[0], g["lat"] + rng.uniform(-4, 4)), attack=fam, sid=sid))

    for _ in range(s_n):                       # low-value "seasoning" to look established
        tap(rng.uniform(3, 15))
        t += _jit(g["season_gap_s"], rng, 0.1)
    for _ in range(c_n):                       # the cash-out
        tap(_jit(g["amount"], rng))
        t += _jit(g["cash_gap_s"], rng, 0.1)
    return rows


def _protocol(w: World, rng: random.Random, sid: int, g: Dict[str, Any], *, fam: str,
              pred: Callable, cdcvm: bool = False, transit: bool = False,
              patch: Optional[Callable[[Dict[str, Any]], None]] = None):
    """A stolen physical card / phone used locally with a protocol-level trick.
    Behaviourally clean: normal latency, home city, no travel."""
    tok = w.alloc_victim(pred)
    if tok is None:
        return []
    anchor = w.pick_anchor(tok, 8 * HOUR, rng)
    if anchor is None:
        return []
    c = w.city[tok["ci"]]
    pool = [x for x in c["retail"] if x not in tok["home_terms"] and x not in c["slow"]]
    t = anchor["timestamp"] + rng.uniform(HOUR, 6 * HOUR)
    rows = []
    for tid in rng.sample(pool, int(g.get("n_taps", 1))):
        x = w.row(tok, t, _jit(g["amount"], rng), tid, c["lat"] + rng.uniform(-.04, .04),
                  c["lon"] + rng.uniform(-.04, .04), c["name"], "GB",
                  min(90.0, max(15.0, rng.gauss(46, 12))), cdcvm=cdcvm, transit=transit,
                  attack=fam, sid=sid)
        if patch:
            patch(x)
        rows.append(x)
        t += rng.uniform(300, 1200)
    w.clear_benign(tok, anchor["timestamp"], rows[-1]["timestamp"] + 1800)
    return rows


# ------------------------------------------------------------------ victim filters
def _any(t): return True
def _wallet(t): return t["provider"] in WALLETS
def _plastic(t): return t["provider"] in PLASTIC
def _card(t): return t["provider"] in PLASTIC or t["provider"] == "eftpos"
def _mc(t): return t["provider"] == "mastercard"
def _apple(t): return t["provider"] == "applepay"


def _expire(x): x["expiry_ym"] = random.Random(x["timestamp"]).choice([202503, 202509, 202601, 202606, 202610])
def _mixup(x): x["aid"] = PROVIDERS["visa"].aid_prefix
def _replay(x): x["_replay"] = True


_RELAY_SPACE = {"lat": ("f", RELAY_FLOOR_MS, 600), "amount": ("f", 5, 600),
                "gap_s": ("log", 60, 2 * DAY), "n_taps": ("i", 1, 3), "tap_gap_s": ("log", 20, HOUR)}


def _sp(**kw):
    d = dict(_RELAY_SPACE)
    d.update(kw)
    return d


FAMILIES: Dict[str, Dict[str, Any]] = {
    # ---- protocol-level (no relay latency at all) -------------------------------
    "transit_abuse": {
        "kind": "protocol", "label": "Express-transit abuse",
        "what": "Stolen locked phone; the no-auth transit entitlement is steered into a retail purchase.",
        "typical": lambda r: {"amount": r.uniform(120, 900), "n_taps": r.randint(1, 2)},
        "space": {"amount": ("f", 60, 900), "n_taps": ("i", 1, 2)},
        "build": lambda w, r, s, g: _protocol(w, r, s, g, fam="transit_abuse", pred=_apple, transit=True),
    },
    "brand_mixup": {
        "kind": "protocol", "label": "Card-brand mix-up",
        "what": "A Mastercard is presented under a Visa application ID to inherit weaker PIN rules.",
        "typical": lambda r: {"amount": r.uniform(150, 600), "n_taps": r.randint(1, 2)},
        "space": {"amount": ("f", 5, 900), "n_taps": ("i", 1, 2)},
        "build": lambda w, r, s, g: _protocol(w, r, s, g, fam="brand_mixup", pred=_mc, patch=_mixup),
    },
    "cvm_tamper": {
        "kind": "protocol", "label": "CVM / PIN-bypass tamper",
        "what": "Stolen plastic card; verification flags are altered to claim on-device verification.",
        "typical": lambda r: {"amount": r.uniform(150, 600), "n_taps": r.randint(1, 2)},
        "space": {"amount": ("f", 101, 900), "n_taps": ("i", 1, 2)},
        "build": lambda w, r, s, g: _protocol(w, r, s, g, fam="cvm_tamper", pred=_plastic, cdcvm=True),
    },
    "expired_card": {
        "kind": "protocol", "label": "Expired card revived (\"Zombie Card\")",
        "what": "An expired card's terminal-facing expiry is rewritten so the terminal accepts it.",
        "typical": lambda r: {"amount": r.uniform(20, 95), "n_taps": r.randint(1, 2)},
        "space": {"amount": ("f", 5, 900), "n_taps": ("i", 1, 2)},
        "build": lambda w, r, s, g: _protocol(w, r, s, g, fam="expired_card", pred=_plastic, patch=_expire),
    },
    "atc_replay": {
        "kind": "protocol", "label": "Cryptogram replay / pre-play",
        "what": "A previously captured transaction is replayed; its counter does not advance.",
        "typical": lambda r: {"amount": r.uniform(20, 95), "n_taps": r.randint(1, 2)},
        "space": {"amount": ("f", 5, 900), "n_taps": ("i", 1, 2)},
        "build": lambda w, r, s, g: _protocol(w, r, s, g, fam="atc_replay", pred=_plastic, patch=_replay),
    },
    # ---- relay against a real cardholder's card / wallet ------------------------
    "latency_shaped": {
        "kind": "relay", "label": "Latency-shaped relay",
        "what": "Relay tuned to sit just under the absolute latency threshold, hours after the last genuine tap.",
        "typical": lambda r: {"lat": _shaped(r), "amount": r.uniform(120, 400),
                              "gap_s": r.uniform(4, 10) * HOUR, "dist_km": r.uniform(100, 400),
                              "n_taps": 1, "tap_gap_s": 60},
        "space": _sp(dist_km=("f", 5, 600)),
        "build": lambda w, r, s, g: _mature_relay(w, r, s, g, fam="latency_shaped", where="domestic", pred=_wallet),
    },
    "pin_phish_retail": {
        "kind": "relay", "label": "Relay with phished PIN",
        "what": "Victim is talked into tapping their card and giving the PIN; high-value retail purchase.",
        "typical": lambda r: {"lat": _shaped(r), "amount": r.uniform(150, 450),
                              "gap_s": r.uniform(4, 10) * HOUR, "dist_km": r.uniform(100, 400),
                              "n_taps": 1, "tap_gap_s": 60},
        "space": _sp(dist_km=("f", 5, 600)),
        "build": lambda w, r, s, g: _mature_relay(w, r, s, g, fam="pin_phish_retail", where="domestic", pred=_card, pin=True),
    },
    "atm_cashout": {
        "kind": "relay", "label": "ATM cash-out relay",
        "what": "Relayed card plus phished PIN used for a contactless ATM withdrawal in another city.",
        "typical": lambda r: {"lat": _shaped(r), "amount": r.uniform(200, 500),
                              "gap_s": r.uniform(3, 10) * HOUR, "n_taps": r.randint(1, 2),
                              "tap_gap_s": r.uniform(60, 240)},
        "space": _sp(),
        "build": lambda w, r, s, g: _mature_relay(w, r, s, g, fam="atm_cashout", where="domestic", pred=_card, pin=True, atm=True),
    },
    "ghost_tap": {
        "kind": "relay", "label": "Classic ghost tap",
        "what": "Unsophisticated cross-border relay minutes after a genuine tap, with full network latency.",
        "typical": lambda r: {"lat": max(180, r.gauss(430, 110)), "amount": max(20, r.gauss(225, 70)),
                              "gap_s": r.uniform(90, 420), "dist_km": r.uniform(1500, 9000),
                              "n_taps": 1, "tap_gap_s": 60},
        "space": _sp(dist_km=("f", 1500, 9000)),
        "build": lambda w, r, s, g: _mature_relay(w, r, s, g, fam="ghost_tap", where="far", pred=_any),
    },
    "stealth_domestic": {
        "kind": "relay", "label": "Stealth domestic relay",
        "what": "Relay to a nearby city with moderate latency, minutes after a genuine tap.",
        "typical": lambda r: {"lat": max(120, r.gauss(190, 40)),
                              "amount": r.uniform(15, 80) if r.random() < .5 else r.uniform(105, 190),
                              "gap_s": r.uniform(120, 900), "dist_km": r.uniform(60, 250),
                              "n_taps": 1, "tap_gap_s": 60},
        "space": _sp(dist_km=("f", 5, 600)),
        "build": lambda w, r, s, g: _mature_relay(w, r, s, g, fam="stealth_domestic", where="domestic", pred=_any),
    },
    "low_and_slow": {
        "kind": "relay", "label": "Low-and-slow drain",
        "what": "Many sub-limit taps spaced just outside the velocity window, each at a different terminal.",
        "typical": lambda r: {"lat": _shaped(r), "amount": r.uniform(40, 98),
                              "gap_s": r.uniform(2, 8) * HOUR, "dist_km": r.uniform(20, 300),
                              "n_taps": r.randint(8, 20), "tap_gap_s": r.uniform(330, 1500)},
        "space": _sp(dist_km=("f", 5, 600), n_taps=("i", 2, 20), tap_gap_s=("log", 20, 2 * DAY)),
        "build": lambda w, r, s, g: _mature_relay(w, r, s, g, fam="low_and_slow", where="domestic", pred=_any, distinct=True),
    },
    "cross_border_shaped": {
        "kind": "relay", "label": "Plausible-travel relay",
        "what": "Shaped relay abroad, timed so the journey looks like a flight the cardholder could have taken.",
        "typical": lambda r: {"lat": _shaped(r), "amount": r.uniform(40, 98),
                              "gap_s": r.uniform(12, 30) * HOUR, "dist_km": r.uniform(350, 1400),
                              "n_taps": r.randint(1, 3), "tap_gap_s": r.uniform(600, 3600)},
        "space": _sp(dist_km=("f", 300, 1500)),
        "build": lambda w, r, s, g: _mature_relay(w, r, s, g, fam="cross_border_shaped", where="near", pred=_any),
    },
    # ---- stolen cards provisioned into attacker-held wallets --------------------
    "fresh_token_cashout": {
        "kind": "relay", "label": "Fresh-wallet cash-out",
        "what": "Stolen card provisioned into a new wallet and cashed out within hours — no history to compare.",
        "typical": lambda r: {"lat": _shaped(r), "amount": r.uniform(150, 450),
                              "age_s": r.uniform(600, 6 * HOUR), "n_tokens": 1, "n_taps": r.randint(1, 3),
                              "tap_gap_s": r.uniform(60, 600), "dist_km": r.uniform(0, 1500),
                              "abroad": int(r.random() < .5)},
        "space": {"lat": ("f", RELAY_FLOOR_MS, 600), "amount": ("f", 5, 600), "age_s": ("log", 60, 30 * DAY),
                  "n_tokens": ("i", 1, 1), "n_taps": ("i", 1, 6), "tap_gap_s": ("log", 20, 2 * DAY),
                  "dist_km": ("f", 0, 3000), "abroad": ("c", [0, 1])},
        "build": lambda w, r, s, g: _fresh(w, r, s, g, fam="fresh_token_cashout"),
    },
    "token_churn": {
        "kind": "relay", "label": "Token churn",
        "what": "Many fresh tokens, one sub-limit tap each, all at one mule terminal — defeats per-token rules.",
        "typical": lambda r: {"lat": _shaped(r), "amount": r.uniform(60, 98),
                              "age_s": r.uniform(600, 6 * HOUR), "n_tokens": r.randint(8, 20), "n_taps": 1,
                              "tap_gap_s": r.uniform(40, 120), "dist_km": r.uniform(0, 300), "abroad": 0},
        "space": {"lat": ("f", RELAY_FLOOR_MS, 600), "amount": ("f", 5, 600), "age_s": ("log", 60, 30 * DAY),
                  "n_tokens": ("i", 2, 20), "n_taps": ("i", 1, 1), "tap_gap_s": ("log", 20, 6 * HOUR),
                  "dist_km": ("f", 0, 600), "abroad": ("c", [0, 1])},
        "build": lambda w, r, s, g: _fresh(w, r, s, g, fam="token_churn"),
    },
    "seasoned_token": {
        "kind": "relay", "label": "Seasoned token",
        "what": "Attacker ages a stolen-card wallet with small relayed taps so its own baseline looks slow, then cashes out.",
        "typical": lambda r: {"season_taps": r.randint(5, 8), "season_gap_s": r.uniform(8, 20) * HOUR,
                              "lat": _shaped(r), "amount": r.uniform(200, 450),
                              "n_cash": r.randint(1, 2), "cash_gap_s": r.uniform(300, 1800)},
        "space": {"season_taps": ("i", 0, 10), "season_gap_s": ("log", 600, DAY), "lat": ("f", RELAY_FLOOR_MS, 250),
                  "amount": ("f", 5, 600), "n_cash": ("i", 1, 10), "cash_gap_s": ("log", 60, 2 * DAY)},
        "build": lambda w, r, s, g: _seasoned(w, r, s, g, fam="seasoned_token"),
    },
}

FAMILY_ORDER = list(FAMILIES)          # constrained victim pools are allocated first
RELAY_FAMILIES = [f for f in FAMILY_ORDER if FAMILIES[f]["kind"] == "relay"]
PROTOCOL_FAMILIES = [f for f in FAMILY_ORDER if FAMILIES[f]["kind"] == "protocol"]


# ============================================================ genome helpers (fuzz)
def sample_space(space: Dict[str, tuple], rng: random.Random) -> Dict[str, Any]:
    g: Dict[str, Any] = {}
    for k, spec in space.items():
        kind = spec[0]
        if k == "lat":                              # the floor is whatever is assumed right now
            g[k] = rng.uniform(_FLOOR[0], _LAT_CAP[0] or spec[2])
        elif kind == "f":
            g[k] = rng.uniform(spec[1], spec[2])
        elif kind == "log":
            g[k] = math.exp(rng.uniform(math.log(spec[1]), math.log(spec[2])))
        elif kind == "i":
            g[k] = rng.randint(spec[1], spec[2])
        else:
            g[k] = rng.choice(spec[1])
    return g


def mutate(g: Dict[str, Any], space: Dict[str, tuple], rng: random.Random) -> Dict[str, Any]:
    h = dict(g)
    for k in rng.sample(list(space), k=min(len(space), rng.randint(1, 2))):
        spec = space[k]
        kind = spec[0]
        if kind == "f":
            lo = _FLOOR[0] if k == "lat" else spec[1]
            hi = (_LAT_CAP[0] or spec[2]) if k == "lat" else spec[2]
            h[k] = min(hi, max(lo, h[k] + rng.gauss(0, 0.12 * (hi - lo))))
        elif kind == "log":
            h[k] = min(spec[2], max(spec[1], h[k] * math.exp(rng.gauss(0, 0.5))))
        elif kind == "i":
            h[k] = min(spec[2], max(spec[1], h[k] + rng.choice([-2, -1, 1, 2])))
        else:
            h[k] = rng.choice(spec[1])
    return h


def _dur(s: float) -> str:
    if s >= DAY:
        return f"{s / DAY:.1f}d"
    if s >= HOUR:
        return f"{s / HOUR:.1f}h"
    if s >= 60:
        return f"{s / 60:.0f}min"
    return f"{s:.0f}s"


def describe(g: Dict[str, Any]) -> str:
    """Compact, human-readable summary of an attack genome for the report."""
    parts = []
    if "lat" in g:
        parts.append(f"{g['lat']:.0f} ms")
    if "amount" in g:
        parts.append(f"£{g['amount']:.0f}/tap")
    if int(g.get("n_tokens", 1)) > 1:
        parts.append(f"{int(g['n_tokens'])} tokens")
    if int(g.get("n_taps", 1)) > 1:
        parts.append(f"{int(g['n_taps'])} taps every {_dur(g['tap_gap_s'])}")
    elif int(g.get("n_tokens", 1)) > 1:
        parts.append(f"every {_dur(g['tap_gap_s'])}")
    if "season_taps" in g:
        parts.append(f"{int(g['season_taps'])} seasoning taps, {int(g['n_cash'])} cash-outs "
                     f"every {_dur(g['cash_gap_s'])}")
    if "gap_s" in g:
        parts.append(f"{_dur(g['gap_s'])} after last genuine tap")
    if "age_s" in g:
        parts.append(f"token {_dur(g['age_s'])} old")
    if "dist_km" in g:
        parts.append(f"{g['dist_km']:.0f} km away")
    return ", ".join(parts)
